package sn.ism.cdsd.crypto;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CryptoImpl implements ICrypto {

    char[] hexTab= {'0', '1','2','3', '4', '5', '6',
     '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

    @Override
     public String bytesToHexString(byte[] bytes) {
        StringBuilder sb=new StringBuilder();
        for (byte b : bytes) {
            char char1=hexTab[b&0xf];
            char char2=hexTab[(b>>4)&0xf];
            
            sb.append(char1); sb.append(char2);
                  
        }
        return sb.toString();
     }
    @Override
    public byte[] hexStringToBytes(String hexString) {
        int len=hexString.length();
        byte[] bytes=new byte[len/2];
        for (int i = 0; i < len; i+=2) {
            char char1=hexString.charAt(i);
            char char2=hexString.charAt(i+1);
            int b1=Integer.parseInt(char1+"", 16);
            int b2=Integer.parseInt(char2+"", 16);
            bytes[i/2]=(byte)(b1|(b2<<4));
        }
        return bytes;
    }

    @Override
    public void saveHexkey(Key hexKey, String filePath) {
        try {
             String contenu=bytesToHexString(hexKey.getEncoded());
             String algo=hexKey.getAlgorithm();
            FileOutputStream fos=new  FileOutputStream(filePath);
            PrintWriter out=new PrintWriter(fos);
            out.print(algo+"|"+contenu);
            out.close();
            fos.close();
            
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public Key loadHexKey(String filePath, String password) {
        FileInputStream fis;
        try {
            fis = new FileInputStream(filePath);
            byte[] data=new byte[fis.available()];
            fis.read(data);
            String contenu=new String(data);
            String[] parts=contenu.split("\\|");
            String algo=parts[0];
            String hexKey=parts[1];
            byte[] bytes=hexStringToBytes(hexKey);
            Key key=new javax.crypto.spec.SecretKeySpec(bytes, algo);
            return key;
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
      return null;
    }

    @Override
    public SecretKey generateKey() {
        // keyGenerator
        // throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
        
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");

            SecureRandom secureRandom = new SecureRandom();
            keyGen.init(256, secureRandom);

            SecretKey secretKey = keyGen.generateKey();
            return secretKey;

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm not supported: " + e.getMessage());
            throw new RuntimeException("Key generation failed", e);
        }
    }

    @Override
    public SecretKey generateKey(String password) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public SecretKey generateKey(String password, String salt) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public SecretKey generateKey(String password, String salt, String algorithm) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public SecretKey generateKey(String password, String salt, String algorithm, int iterationCount) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public SecretKey generateKey(String password, String salt, String algorithm, int iterationCount, int keyLength) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String encrypt(String data, Key key) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String decrypt(String data, Key key) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public KeyPair generateKeyPair() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public KeyPair generateKeyPair(String algorithm) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String encrypt(String data, PublicKey key) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public String decrypt(String data, PrivateKey key) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
}
