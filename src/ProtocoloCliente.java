import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.security.PublicKey;
import java.security.SecureRandom;

public class ProtocoloCliente {

    private static PublicKey llavePublica;

    private static final String rutaLlavePublica = "llave_publica.ser";
    private static final String reto = generarRetoAleatorio(); 

    private static String retoCifrado;

    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        cargarLlavePublica();
        
        int estado = 1;
        boolean ejecutar = true;
        
        while (ejecutar) {
            switch (estado) {
                case 1 : estado = estadoInicial(stdIn, pIn, pOut);
                break;
                case 2 : estado = enviarReto(pOut, pIn);
                break;
                case 3:
                //estado = generarParametrosEImprimir();
            
                break;
                case 4 : estado = manejarComando(stdIn, pIn, pOut);
                break;
                default : {
                    System.out.println("Protocolo terminado o error.");
                    ejecutar = false;
                }
            }
        }
    }

    private static int estadoInicial(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        System.out.println("Escriba el mensaje para enviar: ");
        String fromUser = stdIn.readLine();
        
        if (fromUser.equalsIgnoreCase("SECINIT")) {
            System.out.println("1. Enviando SECINIT...");
            pOut.println("SECINIT");
            return 2; // Avanza al estado de enviar reto
        }
        
        System.out.println("Entrada no válida. Intente nuevamente.");
        return 1;
    }

    private static int enviarReto(PrintWriter pOut, BufferedReader pIn) throws IOException {
        try {
            retoCifrado = Seguridad.cifradoAsimetrico(reto, llavePublica);
            System.out.println("2a. Cifrar reto");
            pOut.println(retoCifrado); // Paso 2b: enviar el reto cifrado
            System.out.println("2b. Enviar reto cifrado");
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error al cifrar y enviar el reto.");
            return 1; // Termina en caso de error
        }
        
        // Espera respuesta del servidor
        String fromServer = pIn.readLine();
        if (fromServer != null) {
            int estadoNuevo= verificarRta(fromServer, pIn, pOut);
            if (estadoNuevo!= 3){
                return estadoNuevo; // Avanza al siguiente estado de comando

            }
        }
        
        System.out.println("Error: Respuesta inesperada del servidor.");
        return 2;
    }

    private static int manejarComando(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        System.out.println("Escriba el mensaje para enviar (OK para terminar): ");
        String fromUser = stdIn.readLine();
        
        if (fromUser != null && !fromUser.isEmpty()) {
            pOut.println(fromUser);
            System.out.println("El usuario escribió: " + fromUser);
            
            // Si el usuario escribe "TERMINAR", termina el protocolo
            if (fromUser.equalsIgnoreCase("TERMINAR")) {
                System.out.println("18. TERMINAR");
                return 3;
            }
            
            // Lee la respuesta del servidor
            String fromServer = pIn.readLine();
            if (fromServer != null) {
                System.out.println("Respuesta del Servidor: " + fromServer);
            }
            
            return 4; // Terminar ???
        }
        
        System.out.println("Entrada no válida.");
        return 3;
    }


    private static int verificarRta(String fromServer,BufferedReader pIn, PrintWriter pOut) throws IOException {
        
        if (fromServer != null && fromServer.equals(reto)) { // Verifica si Rta == Reto
            System.out.println("5. Verificación exitosa de Rta == Reto");
            pOut.println("OK"); // Enviar "OK" como confirmación
            System.out.println("6. Enviar OK");
            return 3; // Avanza al siguiente estado para manejar comandos
        }
        
        System.out.println("Error: Rta no coincide con el Reto.");
        return 0; // Reinicia el protocolo si no coincide
    }


    private static void cargarLlavePublica() {
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

    private static String generarRetoAleatorio() {
        SecureRandom random = new SecureRandom();
        int numeroAleatorio = random.nextInt(90000) + 10000;
        return String.valueOf(numeroAleatorio);
    }


}
