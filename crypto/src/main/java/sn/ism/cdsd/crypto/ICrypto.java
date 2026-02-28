package sn.ism.cdsd.crypto;

import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public interface ICrypto {



    String bytesToHexString(byte[] bytes);
    byte[] hexStringToBytes(String hexString);

    void saveHexkey(Key hexKey, String filePath);
    Key loadHexKey(String filePath, String password);


    /**
     * Génère une clé secrète aléatoire avec l'algorithme AES et une taille de 256 bits
     * @return
     */
    public SecretKey generateKey();
    /**
     * Génère une clé secrète avec l'algorithme AES et une taille de 256 bits à partir d'un mot de passe et d'un sel
     * @param password
     * @return
     */
    public SecretKey generateKey(String password);
    /**
     * Génère une clé secrète avec l'algorithme AES et une taille de 256 bits à partir d'un mot de passe et d'un sel
     * @param password
     * @param salt
     * @return
     */
    public SecretKey generateKey(String password, String salt);
    /**
     * Génère une clé secrète avec  une taille de 256 bits à partir d'un mot de passe et d'un sel
     * @param password
     * @param salt
     * @param algorithm
     * @return
     */
    public SecretKey generateKey(String password, String salt, String algorithm);
    /**
     * Génère une clé secrète avec une taille de 256 bits à partir d'un mot de passe et d'un sel
     * @param password
     * @param salt
     * @param algorithm
     * @param iterationCount
     * @return
     */
    public SecretKey generateKey(String password, String salt, String algorithm, int iterationCount);
    /**
     * Génère une clé secrète 
     * @param password
     * @param salt
     * @param algorithm
     * @param iterationCount
     * @param keyLength
     * @return
     */
    public SecretKey generateKey(String password, String salt, String algorithm, int iterationCount, int keyLength);


    

    /**
     * Chiffre une chaîne de caractères avec une clé secrète
     * @param data
     * @param key
     * @return la chaîne de caractères chiffrée au format Base64 
     */
    public String encrypt(String data, SecretKey key);
    /**
     * Déchiffre une chaîne de caractères chiffrée au format Base64 avec une clé secrète
     * @param data
     * @param key
     * @return la chaîne de caractères déchiffrée en UTF8
     */
    public String decrypt(String data, SecretKey key);

    public KeyPair generateKeyPair();
    public KeyPair generateKeyPair(String algorithm);
    public KeyPair generateKeyPair(String algorithm, int keySize);

    /**
     * Chiffre une chaîne de caractères avec une clé publique
     * @param data
     * @param key
     * @return la chaîne de caractères chiffrée au format Base64
     */
    public String encrypt(String data, PublicKey key);
    /**
     * Déchiffre une chaîne de caractères chiffrée au format Base64 avec une clé privée
     * @param data
     * @param key
     * @return la chaîne de caractères déchiffrée en UTF8
     */
    public String decrypt(String data, PrivateKey key);

}
