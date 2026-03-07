package sn.ism.cdsd.crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
            fis.close();
            return key;
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
      return null;
    }

    @Override
    public SecretKey generateKey() {
        try {
            //SecureRandom sec=SecureRandom.getInstance("SHA1PRNG");
            ////sec.setSeed("graine".getBytes());
            KeyGenerator kg=KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg.generateKey();
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    
    }

    @Override
    public SecretKey generateKey(String password) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public SecretKey generateKey(String password, String salt) {
        return generateKey(password, salt, "AES", 65536, 256);
    }

    @Override
    public SecretKey generateKey(String password, String salt, String algorithm) {
        return generateKey(password, salt, algorithm, 65536, 256);    }

    @Override
    public SecretKey generateKey(String password, String salt, String algorithm, int iterationCount) {
        return generateKey(password, salt, algorithm, iterationCount, 256);
    }

    @Override
    public SecretKey generateKey(String password, String salt, String algorithm, int iterationCount, int keyLength) {
        try {
            // On utilise PBKDF2 pour dériver une clé à partir du mot de passe
            javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            java.security.spec.KeySpec spec = new javax.crypto.spec.PBEKeySpec(
                password.toCharArray(), 
                salt.getBytes(), 
                iterationCount, 
                keyLength
            );
            SecretKey tmp = factory.generateSecret(spec);
            return new javax.crypto.spec.SecretKeySpec(tmp.getEncoded(), algorithm);
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }        
    }

    @Override
    public String encrypt(String data, Key key) {
        try {
            Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv="0123456789ABCDEF".getBytes();
            IvParameterSpec ivspec=new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, key,ivspec );
            
            byte[] enc=cipher.doFinal(data.getBytes());
            
            return bytesToHexString(enc);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        } 
    }

    @Override
    public String decrypt(String data, Key key) {
        try {
            Cipher cipher=Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv="0123456789ABCDEF".getBytes();
            IvParameterSpec ivspec=new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, key,ivspec );
            
            byte[] dec=cipher.doFinal(hexStringToBytes(data));
            
            return new String(dec);
            
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        } 
    }

    @Override
    public KeyPair generateKeyPair() {
        return generateKeyPair("RSA", 2048);
    }

    @Override
    public KeyPair generateKeyPair(String algorithm) {
        return generateKeyPair(algorithm, 2048);
    }

    @Override
    public KeyPair generateKeyPair(String algorithm, int keySize) {
        try {
            java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(algorithm);
            kpg.initialize(keySize);
            return kpg.generateKeyPair();
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    @Override
    public String encrypt(String data, PublicKey key) {
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] enc = cipher.doFinal(data.getBytes());
            return bytesToHexString(enc);
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    @Override
    public String decrypt(String data, PrivateKey key) {
        try {
            Cipher cipher = Cipher.getInstance(key.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] dec = cipher.doFinal(hexStringToBytes(data));
            return new String(dec);
        } catch (Exception ex) {
            Logger.getLogger(CryptoImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
}
