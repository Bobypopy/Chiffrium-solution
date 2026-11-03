package com.chiffrium.application;

import com.chiffrium.application.port.CatalogRequestRepository;
import com.chiffrium.application.port.GroupRepository;
import com.chiffrium.application.security.AccessDeniedException;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.application.security.NotificationService;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.security.CatalogRequest;
import com.chiffrium.domain.security.CatalogRequest.Kind;
import com.chiffrium.domain.security.CatalogRequest.Status;
import com.chiffrium.domain.security.Group;
import com.chiffrium.domain.security.Permission;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Circuit de validation des modifications du catalogue : un utilisateur propose (ex. "classer tel OID comme
 * interdit"), un administrateur accepte (la modification est alors appliquée) ou refuse avec un motif.
 * Les responsables de groupe suivent les demandes de leurs membres.
 */
public final class CatalogRequestService {

    /** Évite qu'un compte inonde les administrateurs de demandes. */
    static final int MAX_PENDING_PER_USER = 20;
    private static final String CATALOG_LINK = "#/catalog";
    private static final Map<Kind, String> KIND_LABELS = Map.of(Kind.CREATE, "ajout",
            Kind.UPDATE, "modification", Kind.DELETE, "retrait");

    private final CatalogRequestRepository requests;
    private final CatalogService catalog;
    private final GroupRepository groups;
    private final AuditService audit;
    private final NotificationService notifier;
    private final Clock clock;

    public CatalogRequestService(CatalogRequestRepository requests, CatalogService catalog, GroupRepository groups,
                                 AuditService audit, NotificationService notifier, Clock clock) {
        this.requests = requests;
        this.catalog = catalog;
        this.groups = groups;
        this.audit = audit;
        this.notifier = notifier;
        this.clock = clock;
    }

    /**
     * @param proposal entrée proposée (obligatoire sauf pour une suppression)
     * @throws IllegalArgumentException          demande incohérente (entrée inconnue, catalogue invalide...)
     * @throws CatalogService.InvalidCatalogException si l'entrée proposée rendrait le catalogue invalide
     */
    public CatalogRequest submit(Actor actor, Kind kind, String algorithmId, AlgorithmDefinition proposal,
                                 String justification, String groupId) {
        actor.require(Permission.REQUEST_CATALOG_CHANGE);
        Objects.requireNonNull(kind, "kind");
        String cleanJustification = text(justification, "Justification obligatoire (référence, besoin...).");
        AlgorithmCatalog current = catalog.catalog();
        boolean exists = algorithmId != null && current.findAlgorithm(algorithmId).isPresent();
        switch (kind) {
            case CREATE -> require(!exists, "Cette entrée existe déjà : proposer une modification.");
            case UPDATE, DELETE -> require(exists, "Entrée inconnue : " + algorithmId);
        }
        if (kind != Kind.DELETE) {
            require(proposal != null && Objects.equals(proposal.id(), algorithmId),
                    "L'entrée proposée doit porter l'identifiant " + algorithmId + ".");
            List<String> errors = current.withAlgorithm(proposal).validate();
            if (!errors.isEmpty()) {
                throw new CatalogService.InvalidCatalogException(errors);
            }
        }
        require(groupId == null || groups.membershipsOf(actor.userId()).stream()
                .anyMatch(m -> m.groupId().equals(groupId)), "Vous n'appartenez pas à ce groupe.");
        long pending = requests.findAll().stream()
                .filter(r -> r.status() == Status.PENDING && r.requestedBy().equals(actor.username())).count();
        require(pending < MAX_PENDING_PER_USER, "Trop de demandes en attente (" + MAX_PENDING_PER_USER + " max).");

        CatalogRequest request = new CatalogRequest(UUID.randomUUID().toString(), kind, algorithmId,
                kind == Kind.DELETE ? null : proposal, cleanJustification, actor.username(), groupId, Status.PENDING,
                null, null, clock.instant(), null);
        requests.save(request);
        audit.record(actor, "CATALOG_REQUEST_SUBMITTED", algorithmId, kind.id() + " : " + cleanJustification);
        String title = actor.username() + " propose : " + KIND_LABELS.get(kind) + " de \"" + algorithmId + "\"";
        notifier.notifyPermission(Permission.EDIT_CATALOG, NotificationService.CATALOG_REQUEST, title,
                cleanJustification, CATALOG_LINK);
        if (groupId != null) {
            groups.findById(groupId).ifPresent(group -> notifier.notifyUsers(group.members().stream()
                    .filter(Group.Member::manager).map(Group.Member::userId)
                    .filter(id -> !id.equals(actor.userId())).toList(),
                    NotificationService.CATALOG_REQUEST, title, cleanJustification, CATALOG_LINK));
        }
        notifier.alert(title, cleanJustification, CATALOG_LINK);
        return request;
    }

    /** Administrateurs : toutes ; responsables de groupe : les leurs et celles de leurs groupes ; autres : les leurs. */
    public List<CatalogRequest> list(Actor actor) {
        if (actor.can(Permission.EDIT_CATALOG)) {
            return requests.findAll();
        }
        Set<String> managed = actor.userId() == null ? Set.of() : groups.membershipsOf(actor.userId()).stream()
                .filter(Group.Membership::manager).map(Group.Membership::groupId).collect(Collectors.toSet());
        return requests.findAll().stream()
                .filter(r -> r.requestedBy().equals(actor.username()) || managed.contains(r.groupId()))
                .toList();
    }

    public CatalogRequest withdraw(Actor actor, String id) {
        CatalogRequest request = pending(id);
        if (!request.requestedBy().equals(actor.username())) {
            throw new AccessDeniedException("Seul l'auteur peut retirer sa demande.");
        }
        CatalogRequest withdrawn = request.decided(Status.WITHDRAWN, actor.username(), null, clock.instant());
        requests.save(withdrawn);
        audit.record(actor, "CATALOG_REQUEST_WITHDRAWN", request.algorithmId(), null);
        return withdrawn;
    }

    /**
     * Décision d'un administrateur. Une acceptation applique la modification (validée et tracée par le
     * {@link CatalogService}) ; un refus exige un motif, communiqué au demandeur.
     */
    public CatalogRequest review(Actor actor, String id, boolean approve, String comment) {
        actor.require(Permission.EDIT_CATALOG);
        CatalogRequest request = pending(id);
        String cleanComment = comment == null || comment.isBlank() ? null : comment.strip();
        if (cleanComment != null && cleanComment.length() > CatalogRequest.MAX_TEXT_LENGTH) {
            throw new IllegalArgumentException("Commentaire trop long.");
        }
        if (approve) {
            if (request.kind() == Kind.DELETE) {
                catalog.remove(actor, request.algorithmId());
            } else {
                catalog.upsert(actor, request.proposal());
            }
        } else {
            require(cleanComment != null, "Indiquer le motif du refus.");
        }
        CatalogRequest decided = request.decided(approve ? Status.APPROVED : Status.REJECTED, actor.username(),
                cleanComment, clock.instant());
        requests.save(decided);
        audit.record(actor, approve ? "CATALOG_REQUEST_APPROVED" : "CATALOG_REQUEST_REJECTED", request.algorithmId(),
                "demande de " + request.requestedBy() + (cleanComment == null ? "" : " : " + cleanComment));
        notifier.notifyUsername(request.requestedBy(), NotificationService.CATALOG_REQUEST,
                "Demande " + (approve ? "acceptée" : "refusée") + " : \"" + request.algorithmId() + "\"",
                cleanComment == null ? "Par " + actor.username() + "." : actor.username() + " : " + cleanComment,
                CATALOG_LINK);
        return decided;
    }

    private CatalogRequest pending(String id) {
        CatalogRequest request = requests.find(id).orElseThrow(() -> new IllegalArgumentException("Demande introuvable."));
        require(request.status() == Status.PENDING, "Cette demande a déjà été traitée.");
        return request;
    }

    private static String text(String value, String missingMessage) {
        String clean = value == null ? "" : value.strip();
        require(!clean.isEmpty(), missingMessage);
        require(clean.length() <= CatalogRequest.MAX_TEXT_LENGTH, "Texte trop long ("
                + CatalogRequest.MAX_TEXT_LENGTH + " caractères max).");
        return clean;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
