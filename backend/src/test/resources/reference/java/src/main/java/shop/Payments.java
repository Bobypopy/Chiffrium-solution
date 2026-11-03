package shop;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class Payments {
    public void seal(byte[] iv, int rounds) throws Exception {
        IvParameterSpec spec = new IvParameterSpec(iv);
        PBEKeySpec pbe = new PBEKeySpec("ignored".toCharArray(), iv, rounds, 256);
    }
}
