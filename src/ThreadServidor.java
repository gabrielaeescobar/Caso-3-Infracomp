import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;

public class ThreadServidor extends Thread {
    private Socket sktCliente = null;
    private int id;
    private ArrayList<Paquete> tabla;

    public ThreadServidor(Socket pSocket, int pId, ArrayList<Paquete> pTabla) {
        this.sktCliente = pSocket;
        this.id = pId;
        this.tabla = pTabla;
    }

    public void run() {
        System.out.println("Inicio de un nuevo thread: " + id);

        try {
            PrintWriter escritor = new PrintWriter(sktCliente.getOutputStream(), true);
            BufferedReader lector = new BufferedReader(new InputStreamReader(sktCliente.getInputStream()));
            // Crear una instancia de ProtocoloServidor
            ProtocoloServidor protocoloServidor = new ProtocoloServidor();
            protocoloServidor.procesar(lector, escritor, tabla);

            escritor.close();
            lector.close();
            sktCliente.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
