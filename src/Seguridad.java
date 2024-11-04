import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Seguridad {
    
    // Asimetrico (RSA)

    public static String cifradoAsimetrico(String mensaje, PublicKey llavePublica){
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
            byte[] textoCifrado = cipher.doFinal(mensaje.getBytes());
            return Base64.getEncoder().encodeToString(textoCifrado);      
        } catch (Exception e) {
            System.err.println("Error al cifrar el mensaje: " + e.getMessage());
            e.printStackTrace();
            return null;        }
    }

    public static String descifradoAsimetrico(String mensajeCifrado, PrivateKey llavePrivada){
     try {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, llavePrivada);
        byte[] textoDescifrado = cipher.doFinal(Base64.getDecoder().decode(mensajeCifrado));
        return new String(textoDescifrado);
     } catch (Exception e) {
        System.err.println("Error al descifrar el mensaje: " + e.getMessage());
        e.printStackTrace();
        return null;
     }
    }

    public static String calcularFirma(String mensaje, PrivateKey llavePrivada){
        try{
            Signature firma = Signature.getInstance("SHA1withRSA");
            firma.initSign(llavePrivada);
            firma.update(mensaje.getBytes());
            byte[] firmaBytes = firma.sign();
            return Base64.getEncoder().encodeToString(firmaBytes);
        } catch (Exception e) {
            System.err.println("Error al calcular la firma: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }


    // Simetrico (AES)

    public static String cifradoSimetrico(String mensaje, SecretKey llaveSimetrica, IvParameterSpec ivVectorIni){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, llaveSimetrica, ivVectorIni);
            byte[] textoCifrado = cipher.doFinal(mensaje.getBytes());
            return Base64.getEncoder().encodeToString(textoCifrado);

        } catch (Exception e) {
            System.err.println("Error al cifrar el mensaje: " + e.getMessage());
            e.printStackTrace();
            return null;        }
    }

    public static String descifradoSimetrico(String mensajeCifrado, SecretKey llaveSimetrica, IvParameterSpec ivVectorIni){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, llaveSimetrica, ivVectorIni);
            byte[] textoDescifrado = cipher.doFinal(Base64.getDecoder().decode(mensajeCifrado));
            return new String(textoDescifrado);

        } catch (Exception e) {
            System.err.println("Error al descifrar el mensaje: " + e.getMessage());
            e.printStackTrace();
            return null;        }
    }
}