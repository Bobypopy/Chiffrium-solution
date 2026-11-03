import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;

/** Projet d'exemple analysé par les tests : relit un coffre écrit par {@link FermetureCoffre}. */
public class OuvertureCoffre {

    private static final int TAILLE_IV = 12;
    private static final int TAILLE_ETIQUETTE = 128;
    private static final String SEL_PAR_DEFAUT = "sel-de-demonstration-2026";
    private static final String FICHIER_CLE_PRIVEE = "privateKey.der";

    public static void main(String[] args) throws Exception {
        Properties coffre = new Properties();
        try (var entree = Files.newBufferedReader(Path.of(args.length > 0 ? args[0] : "coffre.properties"))) {
            coffre.load(entree);
        }
        byte[] clePrivee = Files.readAllBytes(Path.of(FICHIER_CLE_PRIVEE));
        String motDePasse = args.length > 2 ? args[2] : null;

        byte[] cleProtegee = Base64.getDecoder().decode(coffre.getProperty("cle"));
        if (motDePasse != null) {
            cleProtegee = retirerCouchePar(motDePasse, cleProtegee);
        }
        SecretKey cleDonnees = retrouverCle(cleProtegee, clePrivee);
        byte[] clair = dechiffrerDonnees(Base64.getDecoder().decode(coffre.getProperty("donnees")), cleDonnees);
        System.out.write(clair);
    }

    static SecretKey retrouverCle(byte[] cleProtegee, byte[] clePriveeEncodee) throws Exception {
        PrivateKey privee = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(clePriveeEncodee));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privee);
        return new SecretKeySpec(cipher.doFinal(cleProtegee), "AES");
    }

    static byte[] dechiffrerDonnees(byte[] chiffre, SecretKey cle) throws Exception {
        byte[] iv = Arrays.copyOfRange(chiffre, 0, TAILLE_IV);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, cle, new GCMParameterSpec(TAILLE_ETIQUETTE, iv));
        return cipher.doFinal(chiffre, TAILLE_IV, chiffre.length - TAILLE_IV);
    }

    /** Pendant de la couche héritée : AES sans mode, donc ECB. */
    static byte[] retirerCouchePar(String motDePasse, byte[] donnees) throws Exception {
        SecretKey cle = deriverCle(motDePasse);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, cle);
        return cipher.doFinal(donnees);
    }

    static SecretKey deriverCle(String motDePasse) throws Exception {
        SecretKeyFactory fabrique = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec specification = new PBEKeySpec(motDePasse.toCharArray(),
                SEL_PAR_DEFAUT.getBytes(StandardCharsets.UTF_8), 120_000, 256);
        return new SecretKeySpec(fabrique.generateSecret(specification).getEncoded(), "AES");
    }
}
