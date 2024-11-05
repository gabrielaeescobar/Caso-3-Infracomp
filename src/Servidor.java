import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;

public class Servidor {
    private static final String ALGORITMO = "RSA";
    private static final String rutaCarpetaServidor = "src/DatosServidor";
    private static final String rutaLlavePublica = "llave_publica.ser";
    private static final String rutaLlavePrivada = rutaCarpetaServidor + "/llave_privada.ser"; 
    private static PublicKey llavePublica;
    private static PrivateKey llavePrivada;

    public static void main(String args[]) throws IOException {
        ArrayList<Paquete> tabla = tablaDePaquete();
        System.out.println(tabla.get(1).getId()+ tabla.get(1).getUid()+ tabla.get(1).getEstado());
        System.out.println(tabla);
        System.out.println(tabla.size());

    boolean continuar0 = true;

    
    while (continuar0){
        Scanner scanner = new Scanner(System.in);
        System.out.println("Bienvenido al Servidor. Seleccione una opción:");
        System.out.println("1: Generar pareja de llaves asimétricas del servidor y almacenarlas en archivos");
        System.out.println("2: Ejecutar creando los delegados (threads) para cada cliente");
        System.out.println("3: Salir");

        int opcion = scanner.nextInt();
        if (opcion == 1) {
            generarLLavesAsimetrica();
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

    public static void generarLLavesAsimetrica(){
        try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO);
                generator.initialize(1024); // Inicializar el generador con 1024 bits

                KeyPair keyPair = generator.generateKeyPair();
                llavePublica = keyPair.getPublic();
                llavePrivada = keyPair.getPrivate();

                File carpeta = new File(rutaCarpetaServidor);
                if (!carpeta.exists()) {
                    carpeta.mkdir();
                }

                // guardar llaves en el archivo
                guardarLlavesArchivo(rutaLlavePublica, llavePublica);
                guardarLlavesArchivo(rutaLlavePrivada, llavePrivada);

        } catch (Exception e) {
            System.err.println("Error generando llaves asimétricas: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void guardarLlavesArchivo(String rutaArchivo, Object llave){
    try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(rutaArchivo))) {
                oos.writeObject(llave);
                System.out.println("Llave guardada en: " + rutaArchivo);
            } catch (Exception e) {
                System.err.println("Error al guardar la llave en archivo: " + e.getMessage());
                e.printStackTrace();
            }
    }

    public static ArrayList<Paquete> tablaDePaquete(){
        int[] estadosnum = {0, 1, 2, 3, 4, 5, 6};
        String[] estados = {"ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO", "ENENTREGA", "ENTREGADO", "DESCONOCIDO"};
        Random random = new Random();
        ArrayList<Paquete> paquetes = new ArrayList<>();
        for (int i = 0; i<32; i++){
            paquetes.add(new Paquete("pack_"+i, "u_"+i, estadosnum[random.nextInt(estados.length)]));
        }
        return paquetes;
    }

}
