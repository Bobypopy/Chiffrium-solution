package com.chiffrium.infrastructure.mail;

import com.chiffrium.application.settings.Settings;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Envoi SMTP, vérifié contre un faux relais qui parle le protocole et garde tout ce qu'il reçoit.
 */
class SmtpMailSenderTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    @Test
    void sendsAWellFormedMessage() throws Exception {
        try (FakeSmtp relais = new FakeSmtp()) {
            Settings.Email config = new Settings.Email(true, "127.0.0.1", relais.port(), false, "expediteur",
                    "mot-de-passe", "chiffrium@exemple.fr");

            new SmtpMailSender(config, TIMEOUT)
                    .send("alice@exemple.fr", "Analyse terminée : dépôt paiement",
                            "3 actifs interdits.\nVoir le rapport.");

            List<String> dialogue = relais.awaitDialogue();
            assertThat(dialogue).contains("MAIL FROM:<chiffrium@exemple.fr>", "RCPT TO:<alice@exemple.fr>",
                    "DATA", ".", "QUIT");
            // Authentification : compte et mot de passe encodés, jamais en clair sur le fil.
            assertThat(dialogue).contains("AUTH LOGIN",
                    Base64.getEncoder().encodeToString("expediteur".getBytes(StandardCharsets.UTF_8)),
                    Base64.getEncoder().encodeToString("mot-de-passe".getBytes(StandardCharsets.UTF_8)));
            assertThat(dialogue).noneMatch(ligne -> ligne.contains("mot-de-passe"));

            String message = String.join("\n", dialogue);
            assertThat(message).contains("Content-Transfer-Encoding: base64");
            // Objet accentué encodé selon la RFC 2047, corps en base64 : rien n'arrive abîmé.
            assertThat(message).contains("Subject: =?UTF-8?B?"
                    + Base64.getEncoder().encodeToString(
                            "Analyse terminée : dépôt paiement".getBytes(StandardCharsets.UTF_8)) + "?=");
            assertThat(new String(Base64.getDecoder().decode(relais.body()), StandardCharsets.UTF_8))
                    .isEqualTo("3 actifs interdits.\nVoir le rapport.");
        }
    }

    @Test
    void neverSendsCredentialsOverAPlainLinkToARemoteHost() throws Exception {
        try (FakeSmtp relais = new FakeSmtp()) {
            // Même relais, mais annoncé sous un nom qui n'est pas la boucle locale : refus avant l'envoi.
            Settings.Email config = new Settings.Email(true, "relais.exemple.fr", relais.port(), false, "compte",
                    "secret", "chiffrium@exemple.fr");

            assertThatThrownBy(() -> new SmtpMailSender(config, TIMEOUT)
                    .send("alice@exemple.fr", "Objet", "Corps"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("en clair");
        }
    }

    @Test
    void reportsARefusalFromTheRelay() throws Exception {
        try (FakeSmtp relais = new FakeSmtp("RCPT", "550 boîte inconnue")) {
            Settings.Email config = new Settings.Email(true, "127.0.0.1", relais.port(), false, null, null,
                    "chiffrium@exemple.fr");

            assertThatThrownBy(() -> new SmtpMailSender(config, TIMEOUT)
                    .send("absente@exemple.fr", "Objet", "Corps"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("550");
        }
    }

    @Test
    void aRefusedPasswordIsNeverRepeatedInTheError() throws Exception {
        String encoded = Base64.getEncoder().encodeToString("mot-de-passe".getBytes(StandardCharsets.UTF_8));
        try (FakeSmtp relais = new FakeSmtp(encoded, "535 authentification refusée")) {
            Settings.Email config = new Settings.Email(true, "127.0.0.1", relais.port(), false, "expediteur",
                    "mot-de-passe", "chiffrium@exemple.fr");

            assertThatThrownBy(() -> new SmtpMailSender(config, TIMEOUT)
                    .send("alice@exemple.fr", "Objet", "Corps"))
                    .hasMessageContaining("AUTH (mot de passe)")
                    .hasMessageContaining("535")
                    .hasMessageNotContaining(encoded);
        }
    }

    @Test
    void tlsChecksThatTheCertificateNamesTheRelay() throws Exception {
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket()) {
            assertThat(SmtpMailSender.verifyHostName(socket).getSSLParameters().getEndpointIdentificationAlgorithm())
                    .isEqualTo("HTTPS");
        }
    }

    @Test
    void rejectsHeaderInjectionInTheSubject() throws Exception {
        try (FakeSmtp relais = new FakeSmtp()) {
            Settings.Email config = new Settings.Email(true, "127.0.0.1", relais.port(), false, null, null,
                    "chiffrium@exemple.fr");

            new SmtpMailSender(config, TIMEOUT).send("alice@exemple.fr",
                    "Objet\r\nBcc: espion@ailleurs.fr", "Corps");

            List<String> dialogue = relais.awaitDialogue();
            assertThat(dialogue).noneMatch(ligne -> ligne.startsWith("Bcc:"));
            assertThat(dialogue).filteredOn(ligne -> ligne.startsWith("RCPT TO:")).hasSize(1);
        }
    }

    /** Relais SMTP en mémoire : répond correctement, enregistre le dialogue, refuse ce qu'on lui demande. */
    private static final class FakeSmtp implements AutoCloseable {

        private final ServerSocket server = new ServerSocket(0);
        private final CompletableFuture<List<String>> dialogue = new CompletableFuture<>();
        private final String refuseCommand;
        private final String refusal;
        private volatile String body = "";

        FakeSmtp() throws IOException {
            this(null, null);
        }

        FakeSmtp(String refuseCommand, String refusal) throws IOException {
            this.refuseCommand = refuseCommand;
            this.refusal = refusal;
            Thread.ofVirtual().start(this::serve);
        }

        int port() {
            return server.getLocalPort();
        }

        List<String> awaitDialogue() throws Exception {
            return dialogue.get(10, java.util.concurrent.TimeUnit.SECONDS);
        }

        /** Corps seul, sans les en-têtes : ce qui suit la première ligne vide, recollé. */
        String body() {
            int separation = body.indexOf("\n\n");
            return separation < 0 ? body : body.substring(separation + 2).replace("\n", "").strip();
        }

        private void serve() {
            List<String> received = new ArrayList<>();
            try (Socket socket = server.accept();
                 BufferedReader in = new BufferedReader(
                         new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
                out.print("220 faux-relais prêt\r\n");
                out.flush();
                boolean inData = false;
                StringBuilder contenu = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    received.add(line);
                    if (inData) {
                        if (".".equals(line)) {
                            inData = false;
                            body = contenu.toString().strip();
                            out.print("250 message accepté\r\n");
                            out.flush();
                        } else {
                            contenu.append(line).append('\n');
                        }
                        continue;
                    }
                    if (refuseCommand != null && line.startsWith(refuseCommand)) {
                        out.print(refusal + "\r\n");
                        out.flush();
                        continue;
                    }
                    if (line.startsWith("DATA")) {
                        inData = true;
                        // Le corps commence après la ligne vide : on ne garde que ce qui suit.
                        contenu.setLength(0);
                        out.print("354 envoyez le message\r\n");
                    } else if (line.startsWith("QUIT")) {
                        out.print("221 au revoir\r\n");
                        out.flush();
                        break;
                    } else if (line.startsWith("AUTH")) {
                        out.print("334 VXNlcm5hbWU6\r\n");
                    } else if (line.startsWith("EHLO")) {
                        out.print("250-faux-relais\r\n250 AUTH LOGIN\r\n");
                    } else {
                        out.print("250 ok\r\n");
                    }
                    out.flush();
                }
            } catch (IOException e) {
                // Connexion fermée par le client : le dialogue déjà reçu suffit au test.
            }
            dialogue.complete(received);
        }

        @Override
        public void close() throws IOException {
            server.close();
        }
    }
}
