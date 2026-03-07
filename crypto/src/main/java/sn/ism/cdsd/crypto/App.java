package sn.ism.cdsd.crypto;

import java.security.Key;
import java.security.KeyPair;
import java.util.Scanner;

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

            menuTest();

    }
    

    public static void menuTest() {
        ICrypto crypto = new CryptoImpl();
        Scanner scanner = new Scanner(System.in);
        SecretKey aesKey = null;
        KeyPair rsaKeyPair = null;
        String encryptedData = "";

        while (true) {
            System.out.println("\n--- SIMULATION CRYPTO : MENU ---");
            System.out.println("1. Générer une clé AES (256 bits)");
            System.out.println("2. Sauvegarder la clé AES (chemin: /tmp/key.txt)");
            System.out.println("3. Chiffrer un message (AES)");
            System.out.println("4. Déchiffrer le message (AES)");
            System.out.println("5. Générer une paire de clés RSA (2048 bits)");
            System.out.println("6. Tester Chiffrement/Déchiffrement RSA");
            System.out.println("0. Quitter");
            System.out.print("Choix : ");

            int choix = scanner.nextInt();
            scanner.nextLine(); // Consommer le retour ligne

            try {
                switch (choix) {
                    case 1:
                        aesKey = crypto.generateKey();
                        System.out.println("Clé AES générée avec succès !");
                        break;
                    case 2:
                        if (aesKey != null) {
                            crypto.saveHexkey(aesKey, "/tmp/key.txt");
                            System.out.println("Clé sauvegardée dans /tmp/key.txt");
                        } else System.out.println("Erreur : Générez d'abord une clé (Option 1).");
                        break;
                    case 3:
                        if (aesKey != null) {
                            System.out.print("Texte à chiffrer : ");
                            String texte = scanner.nextLine();
                            encryptedData = crypto.encrypt(texte, aesKey);
                            System.out.println("Résultat (Hex) : " + encryptedData);
                        } else System.out.println("Pas de clé AES !");
                        break;
                    case 4:
                        if (aesKey != null && !encryptedData.isEmpty()) {
                            String clair = crypto.decrypt(encryptedData, aesKey);
                            System.out.println("Texte déchiffré : " + clair);
                        } else System.out.println("Rien à déchiffrer.");
                        break;
                    case 5:
                        rsaKeyPair = crypto.generateKeyPair();
                        System.out.println("Paire RSA générée (Publique + Privée).");
                        break;
                    case 6:
                        if (rsaKeyPair != null) {
                            System.out.print("Message secret pour RSA : ");
                            String msg = scanner.nextLine();
                            String rsaEnc = crypto.encrypt(msg, rsaKeyPair.getPublic());
                            System.out.println("Chiffré avec Clé Publique : " + rsaEnc);
                            System.out.println("Déchiffré avec Clé Privée : " + crypto.decrypt(rsaEnc, rsaKeyPair.getPrivate()));
                        } else System.out.println("Générez d'abord la paire RSA (Option 5).");
                        break;
                    case 0:
                        System.exit(0);
                }
            } catch (Exception e) {
                System.out.println("Erreur durant l'opération : " + e.getMessage());
            }
        }

    }

}
