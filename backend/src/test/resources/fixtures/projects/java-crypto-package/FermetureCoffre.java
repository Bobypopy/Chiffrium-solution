import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

/**
 * Projet d'exemple analysé par les tests : chiffre un fichier dans un "coffre".
 *
 * Les données sont chiffrées en AES-GCM avec une clé tirée au hasard, elle-même protégée par RSA. Un mot de
 * passe facultatif ajoute une seconde couche, dérivée par PBKDF2. Le chemin "hérité" est volontairement
 * mauvais (AES sans mode, donc ECB) : c'est ce que les tests doivent voir signaler.
 */
public class FermetureCoffre {

    private static final int TAILLE_IV = 12;
    private static final int TAILLE_ETIQUETTE = 128;
    // Valeur en dur : elle sert à vérifier que l'outil repère les secrets écrits dans le code.
    private static final String SEL_PAR_DEFAUT = "sel-de-demonstration-2026";

    public static void main(String[] args) throws Exception {
        Path source = Path.of(args.length > 0 ? args[0] : "donnees.json");
        Path clePublique = Path.of(args.length > 1 ? args[1] : "publicKey.der");
        String motDePasse = args.length > 2 ? args[2] : null;

        SecretKey cleDonnees = tirerCleDonnees();
        byte[] chiffre = chiffrerDonnees(Files.readAllBytes(source), cleDonnees);
        byte[] cleProtegee = protegerCle(cleDonnees, Files.readAllBytes(clePublique));
        if (motDePasse != null) {
            cleProtegee = ajouterCouchePar(motDePasse, cleProtegee);
        }

        Properties coffre = new Properties();
        coffre.setProperty("donnees", Base64.getEncoder().encodeToString(chiffre));
        coffre.setProperty("cle", Base64.getEncoder().encodeToString(cleProtegee));
        try (var sortie = Files.newBufferedWriter(Path.of("coffre.properties"))) {
            coffre.store(sortie, "coffre de demonstration");
        }
    }

    /** Clé de session : c'est elle qui chiffre réellement les données. */
    static SecretKey tirerCleDonnees() throws Exception {
        KeyGenerator generateur = KeyGenerator.getInstance("AES");
        generateur.init(256);
        return generateur.generateKey();
    }

    static byte[] chiffrerDonnees(byte[] clair, SecretKey cle) throws Exception {
        byte[] iv = new byte[TAILLE_IV];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, cle, new GCMParameterSpec(TAILLE_ETIQUETTE, iv));
        byte[] chiffre = cipher.doFinal(clair);
        byte[] sortie = new byte[iv.length + chiffre.length];
        System.arraycopy(iv, 0, sortie, 0, iv.length);
        System.arraycopy(chiffre, 0, sortie, iv.length, chiffre.length);
        return sortie;
    }

    static byte[] protegerCle(SecretKey cle, byte[] clePubliqueEncodee) throws Exception {
        PublicKey publique = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(clePubliqueEncodee));
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publique);
        return cipher.doFinal(cle.getEncoded());
    }

    /** Couche hérité de la première version du format : AES sans mode, que Java lit en ECB. */
    static byte[] ajouterCouchePar(String motDePasse, byte[] donnees) throws Exception {
        SecretKey cle = deriverCle(motDePasse);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, cle);
        return cipher.doFinal(donnees);
    }

    static SecretKey deriverCle(String motDePasse) throws Exception {
        SecretKeyFactory fabrique = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec specification = new PBEKeySpec(motDePasse.toCharArray(),
                SEL_PAR_DEFAUT.getBytes(StandardCharsets.UTF_8), 120_000, 256);
        return new SecretKeySpec(fabrique.generateSecret(specification).getEncoded(), "AES");
    }
}
