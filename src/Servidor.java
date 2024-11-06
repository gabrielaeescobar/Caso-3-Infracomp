import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;

public class Servidor {
    private static final String ALGORITMO = "RSA";
    private static final String rutaCarpetaServidor = "src/DatosServidor";
    private static final String rutaLlavePublica = "llave_publica.ser";
    private static final String rutaLlavePrivada = rutaCarpetaServidor + "/llave_privada.ser"; 
    private static PublicKey llavePublica;
    private static PrivateKey llavePrivada;
    private static ArrayList<Paquete> tabla= tablaDePaquete();

    
    public static void main(String args[]) throws IOException {
        
        boolean continuar0 = true;

    
        while (continuar0){
            Scanner scanner = new Scanner(System.in);
            System.out.println("Bienvenido al Servidor. Seleccione una opción:");
            System.out.println("1: Generar pareja de llaves asimétricas del servidor y almacenarlas en archivos");
            System.out.println("2: Escenario 2-> Ejecutar creando los delegados (threads) para cada cliente");
            System.out.println("3: Escenario 3-> Ejecutar un solo servidor");

            System.out.println("4: Salir");

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
                    ThreadServidor thread = new ThreadServidor(socket, threadId++, tabla);
                    // aquí debe hacer una modificación porque todos los threads tienen un identificador diferente
            
                    // start
                    thread.start();
                }
                ss.close();
            }
        else if (opcion==3) {
            ServerSocket ss = null;
            //Socket sktCliente = null;

            boolean continuar = true;
            int threadId = 0; 
        
            System.out.println("Main Server ...");
        
            try {
                ss = new ServerSocket(3400);
            } catch (IOException e) {
                System.err.println("No se pudo crear el socket en el puerto: " );
                System.exit(-1);
            }
    
            Socket socket = ss.accept();
        
            try {
                PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                // Crear una instancia de ProtocoloServidor
                for (int i=0; i<32;i++){
                    System.out.println("------INICIO DE CONSULTA "+ i+"------");
                    ProtocoloServidor protocoloServidor = new ProtocoloServidor();
                    protocoloServidor.procesar(lector, escritor, tabla);
                    System.out.println("------FIN DE CONSULTA "+ i+"------");

                }
    
                escritor.close();
                lector.close();
                socket.close();
    
            } catch (IOException e) {
                e.printStackTrace();
            }
            ss.close();
        }      
        else if (opcion==4) continuar0 = false;

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
        int[] estadosnum = {0, 1, 2, 3, 4, 5};
        String[] estados = {"ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO", "ENENTREGA", "ENTREGADO"};
        Random random = new Random();
        ArrayList<Paquete> paquetes = new ArrayList<>();
        for (int i = 0; i<32; i++){
            paquetes.add(new Paquete("pack_"+i, "u_"+i, estadosnum[random.nextInt(estados.length)]));
        }
        return paquetes;
    }
    
    public void escenarioUno(){
        
    }

    
}
