import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class GenerateRSAKeys {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        final KeyPair keyPair = keyGen.generateKeyPair();
        Files.write(Path.of("publicKey"), keyPair.getPublic().getEncoded());
        Files.write(Path.of("privateKey"), keyPair.getPrivate().getEncoded());
    }
}
