import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class Cliente {
    public static final int PUERTO = 3400;
    public static final String SERVIDOR = "localhost";
    public static String uid;
    public static String paqueteid;

    public static void main(String[] args) throws IOException {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Seleccione una opción:");
        System.out.println("1: Ejecutar 32 clientes concurrentes");
        System.out.println("2: Ejecutar clientes uno por uno");

        int opcion = scanner.nextInt();
        scanner.nextLine(); // Consumir el salto de línea

        if (opcion == 1) {
            ejecutarClientesConcurrentes(32);
        } else if (opcion == 2) {
            ejecutarClientesIterativos(scanner);
        } else {
            System.out.println("Opción no válida.");
        }

        scanner.close();
    }  
    
    // ejecutar 32 clientes concurrentes
    public static void ejecutarClientesConcurrentes(int numeroClientes) {
        List<ClienteThread> clientes = new ArrayList<>();

        for (int i = 0; i < numeroClientes; i++) {
            String uid = "user_" + i;
            String paqueteid = "pack_" + i;
            System.out.println("INICIA CLIENTE CON UID: "+uid);

            ClienteThread cliente = new ClienteThread(SERVIDOR, PUERTO, uid, paqueteid);
            clientes.add(cliente);
        }

        // Iniciar los threads
        for (ClienteThread cliente : clientes) {
            cliente.start();
        }

        // Esperar a que todos los threads terminen
        for (ClienteThread cliente : clientes) {
            try {
                cliente.join();
            } catch (InterruptedException e) {
                System.err.println("Error al esperar que el cliente termine: " + e.getMessage());
                e.printStackTrace();
            }
        }

        System.out.println("Todos los clientes han terminado.");
    }


    public static void ejecutarClientesIterativos(Scanner scanner) throws IOException{
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