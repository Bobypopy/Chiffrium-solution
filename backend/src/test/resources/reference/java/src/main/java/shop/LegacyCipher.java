package shop;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public class LegacyCipher {
    private static final String TRANSFORMATION = "DES/ECB/PKCS5Padding";

    public byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, KeyGenerator.getInstance("DES").generateKey());
        return cipher.doFinal(data);
    }

    public byte[] fingerprint(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    public java.security.KeyPair keys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }
}
