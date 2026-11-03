package com.chiffrium.infrastructure.mail;

import com.chiffrium.application.port.MailSender;
import com.chiffrium.application.settings.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Writer;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;

/**
 * Envoi SMTP minimal, sans dépendance : connexion, éventuel STARTTLS, authentification, un message.
 *
 * <p>Seul le strict nécessaire est implémenté (un destinataire, un corps texte), mais deux points ne sont pas
 * négociables : les identifiants ne partent jamais sur une liaison en clair vers un hôte distant, et tout ce
 * qui vient de l'application est nettoyé des retours à la ligne avant d'entrer dans un en-tête - sans quoi un
 * titre de notification pourrait injecter des en-têtes ou des destinataires supplémentaires.
 *
 * <p>Le corps part encodé en base64 : plus de question de longueur de ligne, d'accents ni de point en début
 * de ligne (qui terminerait le message).
 */
public final class SmtpMailSender implements MailSender {

    private static final Logger LOG = LoggerFactory.getLogger(SmtpMailSender.class);
    private static final int OK_MIN = 200;
    private static final int OK_MAX = 399;
    private static final int READY_FOR_DATA = 354;
    private static final int BASE64_LINE = 76;
    /** Port SMTPS : la liaison est chiffrée avant le premier octet, sans STARTTLS. */
    private static final int IMPLICIT_TLS_PORT = 465;
    private static final DateTimeFormatter RFC_5322 =
            DateTimeFormatter.ofPattern("EEE, d MMM yyyy HH:mm:ss Z", Locale.ENGLISH);

    private final Settings.Email config;
    private final int timeoutMillis;

    public SmtpMailSender(Settings.Email config, Duration timeout) {
        this.config = config;
        this.timeoutMillis = (int) timeout.toMillis();
    }

    @Override
    public void send(String to, String subject, String body) {
        String recipient = header(to);
        if (recipient == null || !recipient.contains("@")) {
            throw new IllegalStateException("Adresse destinataire invalide");
        }
        // Vérifié avant d'ouvrir la connexion : inutile d'aller jusqu'au relais pour refuser ensuite.
        if (hasCredentials() && !willBeEncrypted() && !isLoopback()) {
            throw new IllegalStateException("Le relais \"" + config.host() + "\" n'est pas chiffré : les "
                    + "identifiants ne seront pas envoyés en clair. Activez STARTTLS ou le port 465.");
        }
        try (Socket socket = connect()) {
            Session session = new Session(socket);
            session.expect(session.read(), "bannière");
            session.command("EHLO " + helo());
            Socket secured = socket;
            if (!isSecure(socket) && config.startTls()) {
                session.command("STARTTLS");
                secured = upgrade(socket);
                session = new Session(secured);
                session.command("EHLO " + helo());
            }
            authenticate(session, secured);
            session.command("MAIL FROM:<" + header(config.from()) + ">");
            session.command("RCPT TO:<" + recipient + ">");
            session.expect(session.command("DATA"), "DATA", READY_FOR_DATA);
            session.write(message(recipient, subject, body));
            session.command(".");
            session.command("QUIT");
        } catch (IOException e) {
            throw new IllegalStateException("relais SMTP injoignable : " + e.getMessage(), e);
        }
    }

    private Socket connect() throws IOException {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(config.host(), config.port()), timeoutMillis);
        socket.setSoTimeout(timeoutMillis);
        return config.port() == IMPLICIT_TLS_PORT ? upgrade(socket) : socket;
    }

    private Socket upgrade(Socket plain) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket secured = verifyHostName(
                (SSLSocket) factory.createSocket(plain, config.host(), config.port(), true));
        secured.startHandshake();
        return secured;
    }

    /**
     * Sans cela, un SSLSocket accepte tout certificat valide, même émis pour un autre domaine : n'importe qui
     * placé entre Chiffrium et le relais pourrait recueillir les identifiants SMTP.
     */
    static SSLSocket verifyHostName(SSLSocket socket) {
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        socket.setSSLParameters(parameters);
        return socket;
    }

    private boolean hasCredentials() {
        return config.username() != null && !config.username().isBlank();
    }

    /** Vrai si la liaison sera chiffrée : port SMTPS, ou STARTTLS demandé. */
    private boolean willBeEncrypted() {
        return config.port() == IMPLICIT_TLS_PORT || config.startTls();
    }

    private void authenticate(Session session, Socket socket) throws IOException {
        if (!hasCredentials()) {
            return;
        }
        // Filet : si le STARTTLS annoncé n'a finalement pas eu lieu, on s'arrête ici.
        if (!isSecure(socket) && !isLoopback()) {
            throw new IllegalStateException("Le relais \"" + config.host() + "\" n'est pas chiffré : les "
                    + "identifiants ne seront pas envoyés en clair. Activez STARTTLS ou le port 465.");
        }
        Base64.Encoder encoder = Base64.getEncoder();
        session.command("AUTH LOGIN");
        // Un libellé à la place de la valeur : en cas de refus, ni le log ni l'erreur ne contiennent le secret.
        session.command(encoder.encodeToString(config.username().getBytes(StandardCharsets.UTF_8)),
                "AUTH (identifiant)");
        session.command(encoder.encodeToString(
                String.valueOf(config.password()).getBytes(StandardCharsets.UTF_8)), "AUTH (mot de passe)");
    }

    private boolean isLoopback() {
        String host = String.valueOf(config.host()).toLowerCase(Locale.ROOT);
        return "localhost".equals(host) || "127.0.0.1".equals(host) || "::1".equals(host);
    }

    private static boolean isSecure(Socket socket) {
        return socket instanceof SSLSocket;
    }

    /** Nom annoncé au relais : le domaine de l'expéditeur, à défaut "localhost". */
    private String helo() {
        String from = header(config.from());
        int at = from == null ? -1 : from.indexOf('@');
        return at > 0 ? from.substring(at + 1) : "localhost";
    }

    private String message(String recipient, String subject, String body) {
        String encoded = wrap(Base64.getEncoder().encodeToString(
                String.valueOf(body).getBytes(StandardCharsets.UTF_8)));
        return "From: " + header(config.from()) + "\r\n"
                + "To: " + recipient + "\r\n"
                + "Subject: " + encodeHeader(subject) + "\r\n"
                + "Date: " + ZonedDateTime.now().format(RFC_5322) + "\r\n"
                + "MIME-Version: 1.0\r\n"
                + "Content-Type: text/plain; charset=UTF-8\r\n"
                + "Content-Transfer-Encoding: base64\r\n"
                + "Auto-Submitted: auto-generated\r\n"
                + "\r\n"
                + encoded;
    }

    /** Objet accentué : encodage RFC 2047, sans quoi les caractères non ASCII arrivent abîmés. */
    private static String encodeHeader(String value) {
        String clean = header(value);
        if (clean == null || clean.isEmpty()) {
            return "(sans objet)";
        }
        return "=?UTF-8?B?" + Base64.getEncoder().encodeToString(clean.getBytes(StandardCharsets.UTF_8)) + "?=";
    }

    /** Retire tout retour à la ligne : un en-tête ne doit jamais pouvoir en contenir. */
    private static String header(String value) {
        return value == null ? null : value.replaceAll("[\\r\\n]", " ").strip();
    }

    private static String wrap(String base64) {
        StringBuilder wrapped = new StringBuilder(base64.length() + base64.length() / BASE64_LINE * 2);
        for (int i = 0; i < base64.length(); i += BASE64_LINE) {
            wrapped.append(base64, i, Math.min(base64.length(), i + BASE64_LINE)).append("\r\n");
        }
        return wrapped.toString();
    }

    /** Dialogue ligne à ligne avec le relais. */
    private static final class Session {

        private final BufferedReader in;
        private final Writer out;

        Session(Socket socket) throws IOException {
            this.in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            OutputStream stream = socket.getOutputStream();
            this.out = new OutputStreamWriter(stream, StandardCharsets.UTF_8);
        }

        String command(String line) throws IOException {
            return command(line, line.split(" ")[0]);
        }

        String command(String line, String step) throws IOException {
            write(line + "\r\n");
            String response = read();
            expect(response, step);
            return response;
        }

        void write(String text) throws IOException {
            out.write(text);
            out.flush();
        }

        /** Lit une réponse, lignes de continuation comprises ("250-..." puis "250 ..."). */
        String read() throws IOException {
            String line = in.readLine();
            if (line == null) {
                throw new IOException("connexion fermée par le relais");
            }
            while (line.length() > 3 && line.charAt(3) == '-') {
                String next = in.readLine();
                if (next == null) {
                    break;
                }
                line = next;
            }
            return line;
        }

        void expect(String response, String step) {
            expect(response, step, -1);
        }

        void expect(String response, String step, int exactCode) {
            // Texte venu du relais : ses caractères de contrôle ne doivent pas forger de fausses lignes de log.
            String printable = response.replaceAll("\\p{Cntrl}", "?");
            int code;
            try {
                code = Integer.parseInt(response.substring(0, 3));
            } catch (RuntimeException e) {
                throw new IllegalStateException("réponse SMTP illisible après " + step + " : " + printable);
            }
            boolean ok = exactCode > 0 ? code == exactCode : code >= OK_MIN && code <= OK_MAX;
            if (!ok) {
                LOG.debug("SMTP : {} a répondu {}", step, printable);
                throw new IllegalStateException("le relais a refusé \"" + step + "\" : " + printable);
            }
        }
    }
}
