import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class Servidor {

    public static void main(String args[]) throws IOException {
    boolean continuar0 = true;
    
    while (continuar0){
        Scanner scanner = new Scanner(System.in);
        System.out.println("Bienvenido al Servidor. Seleccione una opción:");
        System.out.println("1: Generar pareja de llaves asimétricas del servidor y almacenarlas en archivos");
        System.out.println("2: Ejecutar creando los delegados (threads) para cada cliente");
        System.out.println("3: Salir");

        int opcion = scanner.nextInt();
        if (opcion == 1) {
            System.out.println("Las llaves han sido generadas y almacenadas en archivos.");

        }
        else if (opcion == 2){
            ServerSocket ss = null;
            boolean continuar = true;
            int threadId = 0; 
        
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
                ThreadServidor thread = new ThreadServidor(socket, threadId++);
                // aquí debe hacer una modificación porque todos los threads tienen un identificador diferente
        
                // start
                thread.start();
            }
            ss.close();
        }
        else if (opcion==3) continuar0 = false;

    }

}


}
