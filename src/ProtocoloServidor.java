import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ProtocoloServidor {

    private static PublicKey llavePublica;
    private static PrivateKey llavePrivada;
    private static BigInteger P;
    private static BigInteger G;
    private static BigInteger Gx;
    private static BigInteger x;
    private static BigInteger gy;
    private static SecretKey llaveSimetrica_cifrar; // Llave para cifrado (K_AB1)
    private static SecretKey llaveSimetrica_MAC;    // Llave para MAC (K_AB2)
    private static byte[] iv; // almacena el IV


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

    while (estado < 6 && (inputLine = pIn.readLine()) != null) {
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
                    String mensaje = P.toString()+";" + G.toString()+ ";"+Gx.toString();
                    String firma = Seguridad.calcularFirma(mensaje, llavePrivada);
                    System.out.println("FIRMA: "+firma);
                    outputLine = mensaje+";"+ firma;
                    System.out.println("8. Enviando P, G, Gx y firma al cliente.");
                    estado++;
                } catch (Exception e) {
                    System.err.println("Error al generar los parámetros P, G y G^x: " + e.getMessage());
                    e.printStackTrace();
                    estado = 0; // Reinicia en caso de error
                }
                break;
            
            case 3:
                gy= new BigInteger(inputLine);
                estado = calcularLlavesSimetricas();
                System.out.println("11b. Calcula (G^y)^x");
                System.out.println("estado:"+estado);

                IvParameterSpec ivSpec = generarIV();
                enviarIV(pOut, ivSpec);
                estado++;
               //S System.out.println("Transición al estado 5 después de enviar IV");

                break;

            case 4: 
                break;

            case 5:
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

            System.out.println("7. Genera G, P, G^X");
            
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
    // Método para calcular las llaves simétricas K_AB1 y K_AB2
    private static int calcularLlavesSimetricas() {
        try {
            // Calcular la clave maestra (G^y)^x mod P
            BigInteger claveMaestra = gy.modPow(x, P);
            System.out.println("Clave maestra calculada (G^y)^x mod P: " + claveMaestra);

            // Generar el digest SHA-512 de la clave maestra
            MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512Digest.digest(claveMaestra.toByteArray());

            // Dividir el digest en dos mitades para crear K_AB1 y K_AB2
            byte[] llave_pa_cifrar = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits para cifrado
            byte[] llave_pa_MAC = Arrays.copyOfRange(digest, 32, 64);   // Últimos 256 bits para HMAC

            // Crear llaves SecretKey para cifrado y MAC
            llaveSimetrica_cifrar = new SecretKeySpec(llave_pa_cifrar, "AES");
            llaveSimetrica_MAC = new SecretKeySpec(llave_pa_MAC, "AES");

            System.out.println("Llave simétrica para cifrado (K_AB1): " + new BigInteger(1, llave_pa_cifrar).toString(16));
            System.out.println("Llave simétrica para HMAC (K_AB2): " + new BigInteger(1, llave_pa_MAC).toString(16));

            return 4; // Avanza al siguiente estado
        } catch (Exception e) {
            System.err.println("Error al calcular las llaves simétricas: " + e.getMessage());
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


    private static IvParameterSpec generarIV() {
        byte[] iv = new byte[16]; // IV de 16 bytes
        random.nextBytes(iv); // Genera un IV aleatorio
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // Codificar el IV en Base64 para enviarlo como texto
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        System.out.println("12. iv");
        System.out.println("Vector generado : " + ivBase64);
        
        return ivSpec;
    }

    private static void enviarIV(PrintWriter pOut, IvParameterSpec ivSpec) {
        String ivBase64 = Base64.getEncoder().encodeToString(ivSpec.getIV());
        pOut.println(ivBase64); 
        System.out.println("IV enviado al cliente: " + ivBase64);
    }

}
