import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Decrypts a data file that's been AES encrypted and packaged in a base64 encoded properties file.
 * Decrypts the AES key with RSA encryption, given the public key.
 * Further decrypts the AES key if a package key is provided.
 * Decrypts the data with the decrypted AES key.
 * Outputs the decrypted data to the console.
 */
public class DecryptPackage {
    private static final String USAGE = "Usage: java DecryptPackage.java -packageKey=[PACKAGE] -publicKeyFile=[public-key-file] -packageFile=[data]";
    private static final int TAG_BIT_LENGTH = 128; // 128, 120, 112, 104, 96
    private static final int IV_BYTE_LENGTH = 12;
    private static final int SALT_BYTE_LENGTH = 16;

    private static SecretKey getAESKeyFromPassword(final char[] password, final byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private static String decryptAES(final byte[] bytes, final byte[] key)
            throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        final SecretKey aesKey = new SecretKeySpec(key , 0, key.length, "AES");
        final Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        final byte[] decrypted = aesCipher.doFinal(bytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private static byte[] decryptAESGCM(final byte[] bytes, final String password)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final ByteBuffer bb = ByteBuffer.wrap(bytes);

        final byte[] iv = new byte[IV_BYTE_LENGTH];
        bb.get(iv);
        final byte[] salt = new byte[SALT_BYTE_LENGTH];
        bb.get(salt);
        final byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        try {
            final SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
            final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_BIT_LENGTH, iv));

            return cipher.doFinal(cipherText);
        } catch ( NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException |  InvalidAlgorithmParameterException | InvalidKeyException e) {
            System.err.println("Failed to decrypt using provided key");
            throw e;
        }
    }
    
    private static byte[] decryptPublicRSA(final byte[] bytes, final byte[] publicKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyBytes);
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        final PublicKey publicKey = kf.generatePublic(spec);
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(bytes);        
    } 

    private static byte[] decodeBase64(final byte[] base64) {
        return Base64.getDecoder().decode(base64);
    }

    private static Properties getProperties(final Path packageFile) throws IOException {
        final String packageStrBase64Encoded = Files.readString(packageFile, StandardCharsets.UTF_8).trim();
        final String packageStr = new String(decodeBase64(packageStrBase64Encoded.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8).trim();
        final Properties props = new Properties();
        if (packageStr.startsWith("{")) {
            // package is JSON. (Very Simple JSON - no sub-objects)
            final Matcher matcher = Pattern.compile("([^\"]+)\"\\s*:\\s*(?:\"([^\"]+)\"|(\\d+)),?").matcher(packageStr);

            while (matcher.find()) {
                final String key = matcher.group(1);
                final String value = matcher.group(2);
                if (null != key && null !=value) {
                    props.put(key, value);
                }
            }

            if (props.isEmpty()) {
                System.err.println("Unable to parse JSON into properties. JSON must be simple - one level deep and no object values.");
            }
        } else {
            props.load(new StringReader(packageStr));
        }
        return props;
    }

    public static void main(String[] args) {
        final Map<String, String> commandArgs = Arrays.stream(args)
                .filter(s -> s.startsWith("-"))
                .map(s -> s.substring(1).trim())
                .map(s -> (s.contains("=") ? s : s + "=true"))
                .map(s -> s.split("\\s*=\\s*", 2))
                .filter(s -> s.length == 2 && !s[0].isEmpty() && !s[1].isEmpty())
                .collect(Collectors.toUnmodifiableMap(s -> s[0], s -> s[1]));

        final Path publicKeyFile = Path.of(commandArgs.getOrDefault("publicKeyFile", "publicKey"));
        if (!publicKeyFile.toFile().exists()) {
            System.err.println(USAGE);
            System.err.println("Failed to decrypt. Public key file required: " + publicKeyFile);
            System.exit(-1);
        }

        final Path packageFile = Path.of(commandArgs.getOrDefault("packageFile", "package.txt"));
        if (!packageFile.toFile().exists()) {
            System.err.println(USAGE);
            System.err.println("Failed to decrypt. Package file required: " + packageFile);
            System.exit(-1);
        }

        final Optional<String> packageKey = Optional.ofNullable(commandArgs.get("packageKey"));

        try {

            final Properties props = getProperties(packageFile);

            if (!props.containsKey("_key") || !props.containsKey("_data")) {
                System.err.println("Failed to decrypt. The package is not as expected");
                System.exit(-1);
            }

            final byte[] key = decodeBase64(props.getProperty("_key").getBytes(StandardCharsets.UTF_8));
            final byte[] data = decodeBase64(props.getProperty("_data").getBytes(StandardCharsets.UTF_8));

            // Decrypt the key with the packageKey - if present.
            final byte[] packageKeyBytes = packageKey.isPresent()
                        ? decryptAESGCM(key, packageKey.get())
                        : key;

            // Decrypt the key again, but with RSA public key.
            final byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile);
            final byte[] decryptedAESKey = decryptPublicRSA(packageKeyBytes, publicKeyBytes);

            // Now decrypt the data with the decrypted AES key.
            final String decryptedData = decryptAES(data, decryptedAESKey);

            System.out.println(decryptedData);
        } catch (final Exception e) {
            System.err.println("Failed to decrypt with exception: " + e.getClass().getName() + ":" + e.getMessage());
            if (e instanceof  javax.crypto.IllegalBlockSizeException && packageKey.isEmpty()) {
                System.err.println("Requires a packageKey.");
            } else if (e instanceof AEADBadTagException && packageKey.isPresent()) {
                System.err.println("Wrong value for packageKey.");
            } else if (e instanceof BadPaddingException) {
                System.err.println("Wrong value for publicKey.");
            }
            System.exit(-1);
        }
    }
}
