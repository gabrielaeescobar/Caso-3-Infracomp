import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Random;

public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";
    public int uid;
    
    public static void main(String[] args) throws IOException {
        Socket socket = null;
        PrintWriter escritor = null;
        BufferedReader lector = null;
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
        Random random = new Random();
        int uid = random.nextInt(10000); // Número aleatorio entre 0 y 9999
        System.out.println("UID del cliente: " + uid);

        System.out.println("Comienza cliente");        try {
            socket = new Socket(SERVIDOR, PUERTO);
            escritor = new PrintWriter(socket.getOutputStream(), true);
            lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            ProtocoloCliente.procesar(teclado, lector, escritor,uid);

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
