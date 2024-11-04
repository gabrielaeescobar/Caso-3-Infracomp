import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class Seguridad {
    
    public static String cifradoAsimetrico(String mensaje, PublicKey llavePublica, String algoritmo){
        try {
            Cipher cipher = Cipher.getInstance(algoritmo);
            cipher.init(Cipher.ENCRYPT_MODE, llavePublica);
            byte[] textoCifrado = cipher.doFinal(mensaje.getBytes());
            return Base64.getEncoder().encodeToString(textoCifrado);      
        } catch (Exception e) {
            System.err.println("Error al cifrar el mensaje: " + e.getMessage());
            e.printStackTrace();
            return null;        }
    }

    public static String descifradoAsimetrico(String mensajeCifrado, PublicKey llavePublica, String algoritmo){
     try {
        Cipher cipher = Cipher.getInstance(algoritmo);
        cipher.init(Cipher.DECRYPT_MODE, llavePublica);
        byte[] textoDescifrado = cipher.doFinal(Base64.getDecoder().decode(mensajeCifrado));
        return new String(textoDescifrado);
     } catch (Exception e) {
        System.err.println("Error al descifrar el mensaje: " + e.getMessage());
        e.printStackTrace();
        return null;
     }
    }
}
