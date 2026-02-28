package sn.ism.cdsd.crypto;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
       String chaine="a1398967867843564785feb2";
       CryptoImpl crypto=new CryptoImpl();
       
        byte[] tab = crypto.hexStringToBytes(chaine);
        System.out.println(tab);
        String newChaine = crypto.bytesToHexString(tab);
        System.out.println("nouvelle:"+newChaine);
        System.out.println("olde    :"+chaine);
        System.out.println("key    :"+crypto.generateKey().toString());
        
    }
}
