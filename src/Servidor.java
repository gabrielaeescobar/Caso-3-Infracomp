import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Servidor {

    public static void main(String args[]) throws IOException {
    ServerSocket ss = null;
    boolean continuar = true;
    // aquí va una variable para controlar los identificadores de los threads

    System.out.println("Main Server ...");

    try {
        ss = new ServerSocket(3400);
    } catch (IOException e) {
        System.err.println("No se pudo crear el socket en el puerto: " );
        System.exit(-1);
    }

    while (continuar) {
        // crear el thread y lanzarlo.

        // crear el socket
        Socket socket = ss.accept();

        // crear el thread con el socket y el id
        ThreadServidor thread = new ThreadServidor(socket, 0);
        // aquí debe hacer una modificación porque todos los threads tienen un identificador diferente

        // start
        thread.start();
    }
    ss.close();
}


}
