import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.security.PublicKey;

public class ProtocoloCliente {

    private static PublicKey llavePublica;
    private static final String rutaLlavePublica = "llave_publica.ser";


    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException{
        String fromServer;
        String fromUser;
        boolean ejecutar = true;
        boolean esperarRespuesta = true;
        boolean enviarReto = false;

        cargarLlavePublica();

        // Paso 2a: Generar el reto y cifrarlo
        String reto = "12345"; // puedes usar un número aleatorio o un valor específico
        String retoCifrado = "";

        while (ejecutar){
            if (enviarReto){
                try {
                    retoCifrado = Seguridad.cifradoAsimetrico(reto, llavePublica);
                    System.out.println("2a. Cifrar reto");

                } catch (Exception e) {
                    e.printStackTrace();
                    return; // termina si ocurre un error
                }
        
                pOut.println(retoCifrado);  // Paso 2b: enviar el reto cifrado
                System.out.println("2b. Enviar reto cifrado");

                enviarReto = false;         // Reinicia la variable para no enviar el reto de nuevo
                
            }

            //lee del teclado
            System.out.println("Escriba el msj para enviar: ");
            fromUser = stdIn.readLine();
            


            if (fromUser.equalsIgnoreCase("SECINIT")) {
                esperarRespuesta = false;
                enviarReto = true;
            }


            if (fromUser != null && !fromUser.equals("-1")) {
                System.out.println("El usuario escribió: " + fromUser);
                
                // si lo que ingresa el usuario es "OK"
                if (fromUser.equalsIgnoreCase("OK")) {
                    ejecutar = false;
                }

                //envia por la red
                pOut.println(fromUser);

            }
            else System.out.println("No fue valida la entrada");
            // lee lo q llega por la red
            // si lo que llega del servidor no es null
            // observe la asignacion luego de la condicion
            if (esperarRespuesta && (fromServer = pIn.readLine()) != null) {
                System.out.println("Respuesta del Servidor: " + fromServer);
            }
        }
    }

    
     //  cargar la llave pública desde el archivo
     public static void cargarLlavePublica() {
        llavePublica = (PublicKey) cargarLlaveDesdeArchivo(rutaLlavePublica);
        if (llavePublica != null) {
            System.out.println("0.b Llave pública cargada desde " + rutaLlavePublica);
        }
    }

    private static Object cargarLlaveDesdeArchivo(String rutaArchivo) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(rutaArchivo))) {
            return ois.readObject();
        } catch (Exception e) {
            System.err.println("Error al cargar la llave desde " + rutaArchivo + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

}
