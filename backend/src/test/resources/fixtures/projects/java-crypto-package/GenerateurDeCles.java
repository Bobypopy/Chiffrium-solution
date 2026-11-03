import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/** Projet d'exemple analysé par les tests : produit la paire de clés qui protège les coffres. */
public class GenerateurDeCles {

    static final String FICHIER_CLE_PUBLIQUE = "publicKey.der";
    static final String FICHIER_CLE_PRIVEE = "privateKey.der";

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyPair paire = genererPaire();
        Files.write(Path.of(FICHIER_CLE_PUBLIQUE), paire.getPublic().getEncoded());
        Files.write(Path.of(FICHIER_CLE_PRIVEE), paire.getPrivate().getEncoded());
    }

    static KeyPair genererPaire() throws NoSuchAlgorithmException {
        KeyPairGenerator generateur = KeyPairGenerator.getInstance("RSA");
        generateur.initialize(2048);
        return generateur.generateKeyPair();
    }
}
