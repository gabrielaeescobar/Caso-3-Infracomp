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
    String outputLine;
    int estado = 0;
    cargarLlavePrivada();
    cargarLlavePublica();

    while (estado < 3 && (inputLine = pIn.readLine()) != null) {
        System.out.println("Entrada a procesar: " + inputLine);
        switch (estado) {
            case 0:
                if (inputLine.equalsIgnoreCase("Hola")) {
                    outputLine = "Listo";
                    estado++;
                } else {
                    outputLine = "ERROR. Esperaba Hola";
                    estado = 0;
                }
                break;

            case 1:
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

            case 2:
                if (inputLine.equalsIgnoreCase("OK")) {
                    outputLine = "ADIOS";
                    estado++;
                } else {
                    outputLine = "ERROR. Esperaba OK";
                    estado = 0;
                }
                break;

            default:
                outputLine = "ERROR";
                estado = 0;
        }
        pOut.println(outputLine);
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
