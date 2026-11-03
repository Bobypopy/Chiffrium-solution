package com.chiffrium.application;

import com.chiffrium.application.port.CatalogRepository;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.AuditService;
import com.chiffrium.domain.policy.AlgorithmCatalog;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.security.Permission;

import java.util.ArrayList;
import java.util.List;

/**
 * Consultation et mise à jour du catalogue d'algorithmes (politique cryptographique de l'organisation).
 * Toute modification est validée puis tracée dans le journal d'audit ; elle s'applique aux analyses suivantes.
 */
public final class CatalogService {

    private final CatalogRepository repository;
    private final AuditService audit;
    private final java.time.Clock clock;

    public CatalogService(CatalogRepository repository, AuditService audit) {
        this(repository, audit, java.time.Clock.systemUTC());
    }

    public CatalogService(CatalogRepository repository, AuditService audit, java.time.Clock clock) {
        this.repository = repository;
        this.audit = audit;
        this.clock = clock;
    }

    public AlgorithmCatalog catalog() {
        return repository.load();
    }

    /**
     * OID officiels du catalogue livré avec l'application, pour les proposer pendant la saisie d'une entrée
     * (l'utilisateur garde la main : rien n'est écrit automatiquement).
     */
    public List<OidReference> referenceOids() {
        return repository.defaults().algorithms().stream()
                .filter(a -> !a.oids().isEmpty())
                .map(a -> new OidReference(a.id(), a.name(), a.aliases(), a.oids()))
                .toList();
    }

    /** Entrée de référence : identifiant, nom, alias (pour la reconnaissance) et OID officiels. */
    public record OidReference(String id, String name, List<String> aliases, List<AlgorithmDefinition.OidRef> oids) {
    }

    /**
     * Ajoute ou remplace une entrée après validation du catalogue résultant.
     *
     * @throws InvalidCatalogException si l'entrée rend le catalogue incohérent
     */
    public synchronized AlgorithmCatalog upsert(Actor actor, AlgorithmDefinition definition) {
        actor.require(Permission.EDIT_CATALOG);
        AlgorithmCatalog current = repository.load();
        boolean exists = current.findAlgorithm(definition.id()).isPresent();
        AlgorithmCatalog updated = validated(current.withAlgorithm(definition));
        repository.save(updated);
        audit.record(actor, exists ? "CATALOG_ENTRY_UPDATED" : "CATALOG_ENTRY_CREATED", definition.id(),
                definition.name() + " : " + definition.status().id());
        return updated;
    }

    /**
     * @throws IllegalArgumentException si l'entrée n'existe pas
     */
    public synchronized AlgorithmCatalog remove(Actor actor, String id) {
        actor.require(Permission.EDIT_CATALOG);
        AlgorithmCatalog current = repository.load();
        if (current.findAlgorithm(id).isEmpty()) {
            throw new IllegalArgumentException("Entrée inconnue : " + id);
        }
        List<AlgorithmDefinition> remaining = new ArrayList<>(current.algorithms());
        remaining.removeIf(a -> a.id().equals(id));
        AlgorithmCatalog updated = validated(new AlgorithmCatalog(current.schemaVersion(), remaining, current.modes(),
                current.paddings(), current.curves()));
        repository.save(updated);
        audit.record(actor, "CATALOG_ENTRY_DELETED", id, null);
        return updated;
    }

    /** Remplace tout le catalogue (import de la politique d'une organisation), après validation. */
    public synchronized AlgorithmCatalog replace(Actor actor, AlgorithmCatalog catalog) {
        actor.require(Permission.EDIT_CATALOG);
        AlgorithmCatalog updated = validated(catalog);
        repository.save(updated);
        AlgorithmCatalog.Policy policy = updated.policy();
        audit.record(actor, "CATALOG_IMPORTED", policy == null ? null : policy.name(),
                updated.algorithms().size() + " algorithme(s)"
                        + (policy == null ? "" : ", politique version " + policy.version()
                        + " (" + policy.fingerprint() + ")"));
        return updated;
    }

    /**
     * Publie le catalogue courant comme politique d'entreprise : il pourra être exporté puis importé tel quel
     * sur d'autres installations, qui sauront alors quelle version elles appliquent.
     *
     * <p>Le numéro repart de la version précédente et s'incrémente ; l'empreinte est recalculée sur le
     * contenu, de sorte qu'un catalogue modifié après publication se repère.
     *
     * @param name nom de la politique ; null conserve celui de la publication précédente
     */
    public synchronized AlgorithmCatalog publish(Actor actor, String name) {
        actor.require(Permission.EDIT_CATALOG);
        AlgorithmCatalog current = catalog();
        AlgorithmCatalog.Policy previous = current.policy();
        String label = name != null && !name.isBlank() ? name.strip()
                : previous != null ? previous.name() : "Politique d'entreprise";
        AlgorithmCatalog.Policy policy = new AlgorithmCatalog.Policy(label,
                previous == null ? 1 : previous.version() + 1, actor.username(), clock.instant(),
                current.fingerprint());
        AlgorithmCatalog published = current.withPolicy(policy);
        repository.save(published);
        audit.record(actor, "CATALOG_PUBLISHED", label,
                "version " + policy.version() + " (" + policy.fingerprint() + ")");
        return published;
    }

    private static AlgorithmCatalog validated(AlgorithmCatalog catalog) {
        List<String> errors = catalog.validate();
        if (!errors.isEmpty()) {
            throw new InvalidCatalogException(errors);
        }
        return catalog;
    }

    /** Levée quand une modification rendrait le catalogue invalide. */
    public static final class InvalidCatalogException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final transient List<String> errors;

        public InvalidCatalogException(List<String> errors) {
            super(String.join(" ; ", errors));
            this.errors = List.copyOf(errors);
        }

        public List<String> errors() {
            return errors;
        }
    }
}
