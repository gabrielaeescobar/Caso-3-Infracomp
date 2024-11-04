import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ProtocoloServidor {

    private static PublicKey llavePublica;
    private static PrivateKey llavePrivada;
    private static final String rutaCarpetaServidor = "src/DatosServidor";
    private static final String rutaLlavePrivada = rutaCarpetaServidor + "/llave_privada.ser"; 
    private static final String rutaLlavePublica = "llave_publica.ser";

    public static void procesar(BufferedReader pIn, PrintWriter pOut) throws IOException {
    String inputLine;
    String outputLine = null;
    int estado = 0;
    cargarLlavePrivada();
    cargarLlavePublica();

    while (estado < 4 && (inputLine = pIn.readLine()) != null) {
        System.out.println("Entrada a procesar: " + inputLine);
        switch (estado) {
            case 0:
                //1.            
                if (inputLine.equalsIgnoreCase("SECINIT")) {
                   // System.out.println("1.SECINIT");
                    estado++;
                }
                outputLine = null;
                break;

            case 1:
                // Estado 1: Recibe el reto cifrado y lo descifra
                try {
                    String rta = Seguridad.descifradoAsimetrico(inputLine, llavePrivada);
                    System.out.println("3. Reto descifrado: " + rta);
                    outputLine = rta;   // enviar rta
                    System.out.println("4. Envio de reto descifrado: " + rta);

                    estado ++;          // Cambiar al siguiente estado
                } catch (Exception e) {
                    outputLine = "ERROR al descifrar el reto";
                    estado = 0;          // Volver al inicio si hay un error
                }
                break;

            case 2:
                try {
                    int val = Integer.parseInt(inputLine);
                    val--;
                    outputLine = "" + val;
                    estado++;
                } catch (Exception e) {
                    outputLine = "ERROR en argumento esperado";
                    estado = 0;
                }
                break;

            case 3:
                if (inputLine.equalsIgnoreCase("TERMINAR")) {
                    outputLine = "ADIOS";
                    estado++;
                } else {
                    outputLine = "ERROR. Esperaba TERMINAR";
                    estado = 0;
                }
                break;

            default:
                outputLine = "ERROR";
                estado = 0;
        }

        if (outputLine != null) {
            pOut.println(outputLine);
        }
        
    }
}

    //  cargar la llave pública desde el archivo
    public static void cargarLlavePublica() {
        llavePublica = (PublicKey) cargarLlaveDesdeArchivo(rutaLlavePublica);
        if (llavePublica != null) {
            System.out.println("0.a Llave pública cargada desde " + rutaLlavePublica);
        }
    }

    //  cargar la llave privada desde el archivo
    public static void cargarLlavePrivada() {
        llavePrivada = (PrivateKey) cargarLlaveDesdeArchivo(rutaLlavePrivada);
        if (llavePrivada != null) {
            System.out.println("0.a Llave privada cargada desde " + rutaLlavePrivada);
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
