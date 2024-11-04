import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ProtocoloServidor {

    private static PublicKey llavePublica;
    private static PrivateKey llavePrivada;
    private static BigInteger P;
    private static BigInteger G;
    private static BigInteger Gx;
    private static BigInteger x;
    private static final SecureRandom random = new SecureRandom();
    private static final String rutaCarpetaServidor = "src/DatosServidor";
    private static final String rutaLlavePrivada = rutaCarpetaServidor + "/llave_privada.ser"; 
    private static final String rutaLlavePublica = "llave_publica.ser";

    public static void procesar(BufferedReader pIn, PrintWriter pOut) throws IOException {
    String inputLine;
    String outputLine = null;
    int estado = 0;
    cargarLlavePrivada();
    cargarLlavePublica();

    while (estado < 4 && (inputLine = pIn.readLine()) != null) {
        System.out.println("Entrada a procesar: " + inputLine);
        switch (estado) {
            case 0:
                //1.            
                if (inputLine.equalsIgnoreCase("SECINIT")) {
                   // System.out.println("1.SECINIT");
                    estado++;
                }
                outputLine = null;
                break;

            case 1:
                // Estado 1: Recibe el reto cifrado y lo descifra
                try {
                    String rta = Seguridad.descifradoAsimetrico(inputLine, llavePrivada);
                    System.out.println("3. Reto descifrado: " + rta);
                    outputLine = rta;   // enviar rta
                    System.out.println("4. Envio de reto descifrado: " + rta);

                    estado ++;          // Cambiar al siguiente estado
                } catch (Exception e) {
                    outputLine = "ERROR al descifrar el reto";
                    estado = 0;          // Volver al inicio si hay un error
                }
                break;

            case 2:
                try {
                    generarParametrosEImprimir(); // Generar P, G, y G^x
                    String mensaje = "P:" + P.toString() + ";G:" + G.toString() + ";Gx:" + Gx.toString();
                    String firma = Seguridad.calcularFirma(mensaje, llavePrivada);
                    System.out.println(firma);
                    outputLine = mensaje + ";Firma:"+firma;
                    System.out.println("7. Enviando P, G, Gx y firma al cliente.");
                    estado++;
                } catch (Exception e) {
                    System.err.println("Error al generar los parámetros P, G y G^x: " + e.getMessage());
                    e.printStackTrace();
                    estado = 0; // Reinicia en caso de error
                }
                break;
                
            case 3:
                if (inputLine.equalsIgnoreCase("TERMINAR")) {
                    outputLine = "ADIOS";
                    estado++;
                } else {
                    outputLine = "ERROR. Esperaba TERMINAR";
                    estado = 0;
                }
                break;

            default:
                outputLine = "ERROR";
                estado = 0;
        }

        if (outputLine != null) {
            pOut.println(outputLine);
        }
        
    }
}

public static void generarP_G() throws Exception {
    String ruta_openssl = System.getProperty("user.dir") + "\\lib\\OpenSSL-1.1.1h_win32\\openssl.exe";
    Process process = Runtime.getRuntime().exec(ruta_openssl + " dhparam -text 1024");

    // Leer la salida del comando y acumularla en un StringBuilder
    StringBuilder output = new StringBuilder();
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
        reader.lines().forEach(line -> output.append(line).append("\n"));
    }

    // Espera a que el proceso termine
    int exitCode = process.waitFor();
    if (exitCode != 0) {
        throw new RuntimeException("Error al ejecutar OpenSSL. Código de salida: " + exitCode);
    }

    // Procesar el contenido de `output` para extraer P y G
    extraerP_G(output.toString());
}


    private static void extraerP_G(String output) {
        // Expresión regular para extraer el valor de `prime`
        Pattern primePattern = Pattern.compile("prime:\\s+([0-9a-fA-F:\\s]+)");
        // Expresión regular para extraer el valor de `generator`
        Pattern generatorPattern = Pattern.compile("generator:\\s+(\\d+)");
    
        Matcher primeMatcher = primePattern.matcher(output);
        Matcher generatorMatcher = generatorPattern.matcher(output);
    
        if (primeMatcher.find() && generatorMatcher.find()) {
            // Obtener el valor hexadecimal de `prime` y quitar los `:` y espacios
            String primeHex = primeMatcher.group(1).replaceAll("[:\\s]", "");
            P = new BigInteger(primeHex, 16); // Convertir de hexadecimal a decimal
    
            // Obtener el valor de `generator` como decimal
            G = new BigInteger(generatorMatcher.group(1));
        } else {
            throw new RuntimeException("No se pudo encontrar el valor de P o G en la salida de OpenSSL.");
        }
    }
   // Método para generar G^x
    private static void generarGx() {
    if (P == null || G == null) {
        throw new IllegalStateException("Los valores de P y G deben ser inicializados antes de llamar a generarGx.");
    }

    // Generar un valor secreto x aleatorio en el rango [1, P-1] y calcular G^x mod P
    x = new BigInteger(1024, random).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE); // Guardamos el valor de x
    Gx = G.modPow(x, P); // Calculamos G^x mod P
    }

// Nuevo método para generar parámetros P, G y G^x, e imprimirlos
private static int generarParametrosEImprimir() {
    try {
        // Genera los valores de P y G
        generarP_G();
        
        // Calcula G^x
        generarGx();
        
        // Imprime los valores generados
        System.out.println("Valor de P: " + P);
        System.out.println("Valor de G: " + G);
        System.out.println("Valor de G^x: " + Gx);
        
        return 3; // Avanza al siguiente estado
    } catch (Exception e) {
        System.err.println("Error al generar los parámetros P, G y G^x: " + e.getMessage());
        e.printStackTrace();
        return 0; // Reinicia el protocolo en caso de error
    }
}

    //  cargar la llave pública desde el archivo
    public static void cargarLlavePublica() {
        llavePublica = (PublicKey) cargarLlaveDesdeArchivo(rutaLlavePublica);
        if (llavePublica != null) {
            System.out.println("0.a Llave pública cargada desde " + rutaLlavePublica);
        }
    }

    //  cargar la llave privada desde el archivo
    public static void cargarLlavePrivada() {
        llavePrivada = (PrivateKey) cargarLlaveDesdeArchivo(rutaLlavePrivada);
        if (llavePrivada != null) {
            System.out.println("0.a Llave privada cargada desde " + rutaLlavePrivada);
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

}
