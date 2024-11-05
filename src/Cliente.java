import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";
    public static String uid;
    public static String paqueteid;
        
    public static void main(String[] args) throws IOException {
        Socket socket = null;
        PrintWriter escritor = null;
        BufferedReader lector = null;
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));

        // Solicitar al usuario que ingrese su UID
        System.out.print("Por favor, ingrese su id: ");
        uid = teclado.readLine();

        System.out.print("Por favor, el id del paquete cuyo estado quiere buscar: ");
        paqueteid = teclado.readLine();

        System.out.println("Comienza cliente");        
        try {
            socket = new Socket(SERVIDOR, PUERTO);
            escritor = new PrintWriter(socket.getOutputStream(), true);
            lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));


            ProtocoloCliente.procesar(teclado, lector, escritor,uid,paqueteid);

        } catch (Exception e) {
            e.printStackTrace();
        }

        // escritor.println("Hola");
        // System.out.println(lector.readLine());
        
        socket.close();
        escritor.close();
        lector.close();
    }
}