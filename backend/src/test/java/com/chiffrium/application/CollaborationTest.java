package com.chiffrium.application;

import com.chiffrium.SecurityFixture;
import com.chiffrium.TestSupport;
import com.chiffrium.application.security.AccessDeniedException;
import com.chiffrium.application.security.Actor;
import com.chiffrium.application.security.GroupService;
import com.chiffrium.application.settings.Settings;
import com.chiffrium.domain.model.AnalysisJob;
import com.chiffrium.domain.model.AnalysisRequest;
import com.chiffrium.domain.model.PolicyStatus;
import com.chiffrium.domain.policy.AlgorithmDefinition;
import com.chiffrium.domain.security.CatalogRequest;
import com.chiffrium.domain.security.Group;
import com.chiffrium.domain.security.GroupInvitation;
import com.chiffrium.domain.security.Role;
import com.chiffrium.infrastructure.db.JdbcCatalogRequestRepository;
import com.chiffrium.infrastructure.persistence.FileCatalogRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Travail en équipe : adhésion consentie aux groupes (invitations, demandes, départ), visibilité des analyses par
 * groupe, favoris, demandes de modification du catalogue.
 */
class CollaborationTest {

    private static final String IP = "10.0.0.9";
    private static final AnalysisRequest REQUEST = new AnalysisRequest("https://example.org/a.git", null, true, true,
            true, null);

    private SecurityFixture fx;
    private Actor admin;
    private Actor alice;
    private Actor bob;
    private Actor carol;
    private Group team;

    @BeforeEach
    void open(@TempDir Path dir) {
        fx = new SecurityFixture(dir);
        admin = fx.auth.authenticate(fx.setupAdmin(), IP).actor();
        alice = actor(fx.users.create(admin, "alice", null, null, Role.ANALYST).user().id(), "alice", Role.ANALYST);
        bob = actor(fx.users.create(admin, "bob", null, null, Role.VIEWER).user().id(), "bob", Role.VIEWER);
        carol = actor(fx.users.create(admin, "carol", null, null, Role.ANALYST).user().id(), "carol", Role.ANALYST);
        team = fx.groups.create(admin, "Équipe paiement", "Applications de paiement", Group.Visibility.PRIVATE);
        join(team, alice, false);
        join(team, bob, true);
        fx.groups.leave(admin, team.id());
    }

    /** Invitation par l'administrateur, acceptée par l'intéressé (l'adhésion n'est jamais imposée). */
    private void join(Group group, Actor user, boolean manager) {
        GroupInvitation invitation = fx.groups.invite(admin, group.id(), user.username(), manager, null);
        fx.groups.accept(user, invitation.id());
    }

    @AfterEach
    void close() {
        fx.close();
    }

    private static Actor actor(String id, String username, Role role) {
        return new Actor(id, username, role, IP);
    }

    private static AnalysisJob job(String owner, String groupId) {
        return AnalysisJob.queued(UUID.randomUUID().toString(), REQUEST, owner, groupId, Instant.now());
    }

    @Test
    void analysesAreVisibleToTheirGroupAndManagedByItsManagers() {
        AnalysisAccess access = new AnalysisAccess(fx.groupRepository);
        AnalysisJob shared = job("alice", team.id());
        AnalysisJob personal = job("alice", null);

        assertThat(access.scope(bob).canView(shared)).isTrue();
        assertThat(access.scope(bob).canView(personal)).isFalse();
        assertThat(access.scope(carol).canView(shared)).isFalse();
        assertThat(access.scope(admin).canView(personal)).isTrue();

        assertThat(access.scope(bob).canDelete(shared)).as("responsable du groupe").isTrue();
        assertThat(access.scope(alice).canDelete(personal)).isTrue();
        assertThat(access.scope(carol).canDelete(shared)).isFalse();

        assertThat(access.scope(alice).canUseGroup(team.id())).isTrue();
        assertThat(access.scope(carol).canUseGroup(team.id())).isFalse();
    }

    @Test
    void membershipRequiresTheConsentOfTheInvitedUser() {
        GroupInvitation invitation = fx.groups.invite(bob, team.id(), "carol", false, "Rejoins-nous");
        assertThat(fx.groups.memberships(carol)).as("pas de membre avant acceptation").isEmpty();
        assertThat(fx.groups.myInvitations(carol).received()).extracting(GroupInvitation::id)
                .containsExactly(invitation.id());
        assertThat(fx.notifications.unreadCount(carol)).isEqualTo(1);
        assertThatThrownBy(() -> fx.groups.accept(bob, invitation.id())).as("seul l'invité répond")
                .isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> fx.groups.invite(alice, team.id(), "carol", false, null))
                .as("un simple membre n'invite pas").isInstanceOf(AccessDeniedException.class);

        fx.groups.decline(carol, invitation.id());
        assertThat(fx.groups.memberships(carol)).isEmpty();
        assertThatThrownBy(() -> fx.groups.accept(carol, invitation.id())).hasMessageContaining("déjà");

        GroupInvitation again = fx.groups.invite(bob, team.id(), "carol", false, null);
        fx.groups.accept(carol, again.id());
        assertThat(fx.groups.memberships(carol)).singleElement().extracting(Group.Membership::manager).isEqualTo(false);
        assertThat(fx.audit.all()).extracting(e -> e.action())
                .contains("GROUP_INVITATION_SENT", "GROUP_INVITATION_DECLINED", "GROUP_MEMBER_JOINED");
    }

    @Test
    void publicGroupsAcceptJoinRequestsReviewedByManagers() {
        Group open = fx.groups.create(alice, "Veille crypto", null, Group.Visibility.PUBLIC);
        assertThat(fx.groups.directory(carol)).extracting(GroupService.GroupView::name)
                .as("groupe public visible, groupe privé masqué").contains("Veille crypto").doesNotContain(team.name());
        assertThatThrownBy(() -> fx.groups.requestJoin(carol, team.id(), null))
                .isInstanceOf(AccessDeniedException.class);

        GroupInvitation request = fx.groups.requestJoin(carol, open.id(), "Intéressée");
        assertThat(fx.groups.directory(carol)).filteredOn(v -> v.id().equals(open.id()))
                .singleElement().extracting(GroupService.GroupView::joinRequested).isEqualTo(true);
        assertThatThrownBy(() -> fx.groups.accept(carol, request.id())).isInstanceOf(AccessDeniedException.class);
        fx.groups.accept(alice, request.id());
        assertThat(fx.groups.memberships(carol)).extracting(Group.Membership::groupId).containsExactly(open.id());
    }

    @Test
    void membersCanLeaveButTheLastManagerMustHandOver() {
        fx.groups.leave(alice, team.id());
        assertThat(fx.groups.memberships(alice)).isEmpty();

        join(team, carol, false);
        assertThatThrownBy(() -> fx.groups.leave(bob, team.id())).hasMessageContaining("dernier responsable");
        assertThatThrownBy(() -> fx.groups.setManager(bob, team.id(), bob.userId(), false))
                .hasMessageContaining("au moins un responsable");
        fx.groups.setManager(bob, team.id(), carol.userId(), true);
        fx.groups.leave(bob, team.id());
        assertThat(fx.groups.memberships(carol)).singleElement().extracting(Group.Membership::manager).isEqualTo(true);
        assertThatThrownBy(() -> fx.groups.removeMember(carol, team.id(), carol.userId()))
                .hasMessageContaining("quittez");
    }

    @Test
    void groupCreationFollowsTheCollaborationSetting() {
        Group own = fx.groups.create(carol, "Projet Carol", null, null);
        assertThat(own.visibility()).isEqualTo(Group.Visibility.PRIVATE);
        assertThat(own.isManager(carol.userId())).isTrue();
        assertThatThrownBy(() -> fx.groups.create(admin, "équipe PAIEMENT", null, null)).hasMessageContaining("déjà");

        fx.settings.update(admin, new Settings(null, null, null, null, null, null, null,
                new Settings.Collaboration(false), null, null));
        assertThatThrownBy(() -> fx.groups.create(carol, "Autre", null, null)).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void favoritesArePersonal() {
        String analysis = UUID.randomUUID().toString();
        fx.favoriteRepository.add(alice.userId(), analysis);
        fx.favoriteRepository.add(alice.userId(), analysis);
        assertThat(fx.favoriteRepository.analysisIds(alice.userId())).containsExactly(analysis);
        assertThat(fx.favoriteRepository.analysisIds(bob.userId())).isEmpty();
        fx.favoriteRepository.removeAnalysis(analysis);
        assertThat(fx.favoriteRepository.analysisIds(alice.userId())).isEmpty();
    }

    @Test
    void catalogChangesGoThroughAdministratorReview(@TempDir Path dir) {
        CatalogService catalog = new CatalogService(new FileCatalogRepository(dir.resolve("catalog.json"),
                TestSupport.MAPPER), fx.audit);
        CatalogRequestService requests = new CatalogRequestService(
                new JdbcCatalogRequestRepository(fx.database, TestSupport.MAPPER), catalog, fx.groupRepository,
                fx.audit, fx.notifications, fx.clock);
        AlgorithmDefinition sha1 = catalog.catalog().findAlgorithm("sha-1").orElseThrow();
        AlgorithmDefinition forbidden = new AlgorithmDefinition(sha1.id(), sha1.name(), sha1.primitive(),
                sha1.assetType(), sha1.aliases(), sha1.tokens(), sha1.oids(), PolicyStatus.DISALLOWED,
                sha1.quantumVulnerable(), sha1.keySizeRules(), null, null, sha1.note(), sha1.recommendation(),
                sha1.references());

        CatalogRequest request = requests.submit(alice, CatalogRequest.Kind.UPDATE, "sha-1", forbidden,
                "Politique interne : SHA-1 interdit dès maintenant", team.id());
        assertThat(catalog.catalog().findAlgorithm("sha-1").orElseThrow().status()).isNotEqualTo(PolicyStatus.DISALLOWED);
        assertThat(requests.list(bob)).as("responsable du groupe").extracting(CatalogRequest::id).contains(request.id());
        assertThat(requests.list(carol)).isEmpty();
        assertThatThrownBy(() -> requests.review(alice, request.id(), true, null)).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> requests.review(admin, request.id(), false, " ")).hasMessageContaining("motif");

        CatalogRequest approved = requests.review(admin, request.id(), true, "Validé en comité");
        assertThat(approved.status()).isEqualTo(CatalogRequest.Status.APPROVED);
        assertThat(catalog.catalog().findAlgorithm("sha-1").orElseThrow().status()).isEqualTo(PolicyStatus.DISALLOWED);
        assertThatThrownBy(() -> requests.review(admin, request.id(), true, null)).hasMessageContaining("déjà");

        CatalogRequest other = requests.submit(carol, CatalogRequest.Kind.DELETE, "md5", null, "Test", null);
        assertThatThrownBy(() -> requests.withdraw(alice, other.id())).isInstanceOf(AccessDeniedException.class);
        assertThat(requests.withdraw(carol, other.id()).status()).isEqualTo(CatalogRequest.Status.WITHDRAWN);
        assertThat(fx.audit.all()).extracting(e -> e.action())
                .contains("CATALOG_REQUEST_SUBMITTED", "CATALOG_REQUEST_APPROVED", "CATALOG_ENTRY_UPDATED",
                        "CATALOG_REQUEST_WITHDRAWN");
        assertThat(fx.audit.verify().intact()).isTrue();
        assertThat(List.of(approved.reviewedBy())).containsExactly("admin");
    }
}
