package shop;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class ModernCipher {
    public byte[] encrypt(byte[] data) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, generator.generateKey(), new GCMParameterSpec(128, nonce));
        return cipher.doFinal(data);
    }
}
