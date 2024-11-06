import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ClienteThread extends Thread {
    private String hostName;
    private int portNumber;
    private String uid;
    private String paqueteid;

    public ClienteThread(String hostName, int portNumber, String uid, String paqueteid) {
        this.hostName = hostName;
        this.portNumber = portNumber;
        this.uid = uid;
        this.paqueteid = paqueteid;
    }

    public void run() {
        System.out.println("-------------- INICIA CLIENTE CON UID: "+uid +  " --------------");

        try (
            Socket socket = new Socket(hostName, portNumber);
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
        ) {
            System.out.println("Comienza cliente " + uid);
            ProtocoloCliente.procesar(teclado, lector, escritor, uid, paqueteid);
        } catch (Exception e) {
            System.err.println("Error en ClienteThread: " + e.getMessage());
            e.printStackTrace();
        }
        System.out.println("-------------- TERMINO CLIENTE CON UID: "+uid +  " --------------");

    }
}
