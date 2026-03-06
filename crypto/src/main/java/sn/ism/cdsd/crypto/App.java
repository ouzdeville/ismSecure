package sn.ism.cdsd.crypto;

import java.security.Key;
import javax.crypto.SecretKey;

/**
 * Hello world!
 *
 */
public class App {

    public static void main(String[] args) {
        String chaine = "a1398967867843564785feb2";
        CryptoImpl crypto = new CryptoImpl();
        SecretKey k = crypto.generateKey();
        System.out.println(crypto.bytesToHexString(k.getEncoded()));
        crypto.saveHexkey(k, "security.txt");
        Key k2 = crypto.loadHexKey("security.txt", "");
        System.out.println(crypto.bytesToHexString(k2.getEncoded()));

    }
}
