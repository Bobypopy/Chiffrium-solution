import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Encrypts a data file and packages in a base64 encoded properties file.
 * Encrypts the data with AES encryption from a generated key.
 * Encrypts the generated key with RSA encryption, given the private key.
 * Further encrypts the key with AES encryption if a package key is provided.
 */
public class EncryptPackage {
    private static final String USAGE = "Usage: java EncryptPackage.java -packageKey=[PACKAGE] -privateKeyFile=[private-key-file] [ -dataFile=[DataFile] | [-dataPackage.Key=[Value]]* ] [-metaProperty.key=value]*";
    private static final Set<String> EXCLUDE_KEYS = Set.of("_data", "_key");
    private static final int TAG_BIT_LENGTH = 128; // 128, 120, 112, 104, 96
    private static final int IV_BYTE_LENGTH = 12;
    private static final int SALT_BYTE_LENGTH = 16;

    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        final SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        final KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private static byte[] randomBytes(int length) {
        final SecureRandom random = new SecureRandom();
        final byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static byte[] encryptAESGCM(final byte[] bytes, final String password) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        final byte[] salt = randomBytes(SALT_BYTE_LENGTH);
        final byte[] iv = randomBytes(IV_BYTE_LENGTH);

        final SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_BIT_LENGTH, iv));

        final byte[] encryptedBytes = cipher.doFinal(bytes);

        return ByteBuffer.allocate(iv.length + salt.length + encryptedBytes.length)
                .put(iv) // prefix IV
                .put(salt) // prefix Salt
                .put(encryptedBytes) // add encrypted bytes.
                .array();
    }

    private static String encryptAES(final SecretKey sk, final byte[] toEncrypt) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        final Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, sk);
        return encodeBase64(aesCipher.doFinal(toEncrypt));
    }

    private static String encodeBase64(final byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static void main(final String[] args) {
        final Map<String, String> commandArgs = Arrays.stream(args)
                .filter(s -> s.startsWith("-"))
                .map(s -> s.substring(1).trim())
                .map(s -> (s.contains("=") ? s : s + "=true"))
                .map(s -> s.split("\\s*=\\s*", 2))
                .filter(s -> s.length == 2 && !s[0].isEmpty() && !s[1].isEmpty())
                .collect(Collectors.toUnmodifiableMap(s -> s[0], s -> s[1]));

        final Path privateKeyFile = Path.of(commandArgs.getOrDefault("privateKeyFile", "privateKey"));
        if (!privateKeyFile.toFile().exists()) {
            System.err.println(USAGE);
            System.err.println("Private key file required: " + privateKeyFile);
            System.exit(-1);
        }

        final String dataPropertyPrefix = "dataProperty.";
        final Map<String, String> dataProps = commandArgs.entrySet().stream()
                .filter(e -> e.getKey().startsWith(dataPropertyPrefix))
                .collect(Collectors.toUnmodifiableMap(e -> e.getKey().substring(dataPropertyPrefix.length()), Map.Entry::getValue));

        if (!dataProps.isEmpty() && commandArgs.containsKey("dataFile")) {
            System.err.println(USAGE);
            System.err.println("Cannot have both -dataProperty AND -dataFile to encrypt");
            System.exit(-1);
        }

        final String metaPropertyPrefix = "metaProperty.";
        final Map<String, String> metaProps = commandArgs.entrySet().stream()
                .filter(e -> e.getKey().startsWith(metaPropertyPrefix))
                .map(e -> Map.entry(e.getKey().substring(metaPropertyPrefix.length()), e.getValue()))
                .filter(e -> !EXCLUDE_KEYS.contains(e.getKey()))
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));

        try {
            final String dataStr;
            if (dataProps.isEmpty()) {
                final Path dataFile = Path.of(commandArgs.getOrDefault("dataFile", "data.json"));
                if (!dataFile.toFile().exists()) {
                    System.err.println(USAGE);
                    System.err.println("input data required: " + dataFile);
                    System.exit(-1);
                }
                dataStr = Files.readString(dataFile, StandardCharsets.UTF_8);
            } else {
                final StringBuilder sb = new StringBuilder();
                dataProps.forEach((k,v) -> sb.append(k).append("=").append(v).append("\n"));
                dataStr = sb.toString();
            }

            final byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile);

            // AES - encrypt data using AES
            final KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(256); // The AES key size in number of bits
            final SecretKey dataSecretKey = generator.generateKey();

            final String encryptedDataBase64 = encryptAES(dataSecretKey, dataStr.getBytes());

            // RSA - encrypt AES key using RSA
            final Cipher rsaCipher = Cipher.getInstance("RSA");
            final KeyFactory kf = KeyFactory.getInstance("RSA");
            final PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
            rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            final byte[] encryptedKeyBytes = rsaCipher.doFinal(dataSecretKey.getEncoded());

            // AES - encrypt the AES key again with the package key if provided.
            final Optional<String> packageKey = Optional.ofNullable(commandArgs.get("packageKey"));
            final String encryptedPackageKeyBase64 = encodeBase64(packageKey.isPresent()
                    ? encryptAESGCM(encryptedKeyBytes, packageKey.get())
                    : encryptedKeyBytes);

            final StringBuilder sb = new StringBuilder();
            if ("JSON".equals(commandArgs.get("packageAs"))) {
                sb.append("{\n\"_key\":\"").append(encryptedPackageKeyBase64).append("\",\n");
                sb.append("\"_data\":\"").append(encryptedDataBase64).append("\"");
                metaProps.forEach((k, v) -> sb.append(",\n\"").append(k).append("\":\"").append(v).append("\""));
                sb.append("\n}");
            } else {
                sb.append("_key=").append(encryptedPackageKeyBase64).append("\n");
                sb.append("_data=").append(encryptedDataBase64).append("\n");
                metaProps.forEach((k, v) -> sb.append(k).append("=").append(v).append("\n"));
            }

            final String base64encodedPak = encodeBase64(sb.toString().getBytes(StandardCharsets.UTF_8));

            System.out.println(base64encodedPak);
        } catch (final Exception e) {
            System.err.println("Failed to encrypt with exception: " + e.getClass().getName() + ":" + e.getMessage());
            System.exit(-1);
        }
    }
}