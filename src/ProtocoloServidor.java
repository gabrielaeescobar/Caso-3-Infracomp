import java.math.BigInteger;
import javax.crypto.spec.*;
import java.util.regex.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import java.io.*;


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
    private static IvParameterSpec ivSpec; // almacena el IV
    private static String uid;
    private static String uidDescifrado; // Declaración de uidDescifrado como variable de instancia
    private static boolean hmac1Verificado;
    private static boolean hmac2Verificado;
    private static String packIdDescifrado;
    private static String estadoPaquete="";
    private static long tiempoEjecucion1, tiempoEjecucion2, tiempoEjecucion3, tiempoEjecucionTot; 

    private static final SecureRandom random = new SecureRandom();
    private static final String rutaCarpetaServidor = "src/DatosServidor";
    private static final String rutaLlavePrivada = rutaCarpetaServidor + "/llave_privada.ser"; 
    private static final String rutaLlavePublica = "llave_publica.ser";

    public static void procesar(BufferedReader pIn, PrintWriter pOut, ArrayList<Paquete> tabla) throws IOException {

        String inputLine;
        String outputLine = null;
        int estado = 0;
        cargarLlavePrivada();
        cargarLlavePublica();

        while (estado < 10 && (inputLine = pIn.readLine()) != null) {
            outputLine = null; // Inicializar outputLine a null en cada iteración

            System.out.println("Entrada a procesar: " + inputLine);
            switch (estado) {
                case 0:
                    //1.            
                    if (inputLine.equalsIgnoreCase("SECINIT")) {
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

                        long inicioTiempo = System.currentTimeMillis(); // Inicio del cronómetro
                        generarParametrosEImprimir(); // Generar P, G, y G^x
                        long finTiempo = System.currentTimeMillis(); // Fin del cronómetro
                        long tiempoEjecucion = finTiempo - inicioTiempo;
                        System.out.println("### Tiempo de generación de P, G y G^x: " + tiempoEjecucion + " ms");


                        String mensaje = P.toString()+";" + G.toString()+ ";"+Gx.toString();


                        String firma = Seguridad.calcularFirma(mensaje, llavePrivada);
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
                    // Nuevo estado para manejar la respuesta del cliente
                    if (inputLine.equalsIgnoreCase("OK")) {
                        System.out.println("Cliente envió OK");
                        estado++; // Proceder al siguiente estado para recibir G^y
                    } else if (inputLine.equalsIgnoreCase("ERROR")) {
                        System.out.println("Cliente envió ERROR");
                        estado = 0; // Reiniciar protocolo
                    } else {
                        System.out.println("Mensaje no esperado del cliente: " + inputLine);
                        estado = 0; // Reiniciar protocolo
                    }
                    break;

                case 4:
                    gy= new BigInteger(inputLine);
                     calcularLlavesSimetricas();
                    System.out.println("11b. Calcula (G^y)^x");

                    ivSpec = generarIV();
                    enviarIV(pOut, ivSpec);
                    estado++;
                    System.out.println("================================+ "+ estado);

                    break;

                case 5: 
                    // Paso 15: Verificar UID y paquete_id con sus respectivos HMAC en un solo paso
                    try {
                        long inicioTiempo1 = System.currentTimeMillis(); // Inicio del cronómetro
                        uidDescifrado = descrifradoSimetricoId(inputLine, llaveSimetrica_cifrar, ivSpec);
                        System.out.println("15.a Descifrar uid");
                        estado++;
                        long finTiempo1 = System.currentTimeMillis(); // Fin del cronómetro
                        tiempoEjecucion1 = finTiempo1 - inicioTiempo1;

                    } catch (Exception e) {
                        System.err.println("Error al verificar UID y paquete ID: " + e.getMessage());
                        e.printStackTrace();
                        estado = 0; // Reinicia en caso de error
                    }
                    break;

                case 6:
                    long inicioTiempo2 = System.currentTimeMillis(); // Inicio del cronómetro

                    hmac1Verificado= verificarHMacUid(inputLine, llaveSimetrica_MAC, uidDescifrado);
                    if (hmac1Verificado){
                        estado++;
                        System.out.println("15.b HMAC uid verificado");
                        long finTiempo2 = System.currentTimeMillis(); // Fin del cronómetro
                        tiempoEjecucion2 = finTiempo2 - inicioTiempo2;


                    } else {
                        estado = 0;
                        System.out.println("Error en el procesamiento de HMAC de uid");
                    }
                    break;
                case 7:
                    long inicioTiempo3 = System.currentTimeMillis(); // Inicio del cronómetro

                    packIdDescifrado = descrifradoSimetricoId(inputLine, llaveSimetrica_cifrar, ivSpec);
                    System.out.println("15.c Descifrar packid");
                    estado++;
                    long finTiempo3 = System.currentTimeMillis(); // Fin del cronómetro
                    tiempoEjecucion3 = finTiempo3 - inicioTiempo3;
                    break;

                case 8:
                    long inicioTiempo4 = System.currentTimeMillis(); // Inicio del cronómetro

                    hmac2Verificado= verificarHMacUid(inputLine, llaveSimetrica_MAC, packIdDescifrado);
                    if (hmac2Verificado){
                        estado++;
                        System.out.println("15.d HMAC packid verificado");
                        long finTiempo4 = System.currentTimeMillis(); // Fin del cronómetro
                        tiempoEjecucionTot = (finTiempo4 - inicioTiempo4)+tiempoEjecucion1+tiempoEjecucion2+tiempoEjecucion3;
                        System.out.println("### Tiempo en ejecutar el paso 15: " + tiempoEjecucion1 + " ms");;
    
                        if (hmac1Verificado&&hmac2Verificado){
                            ArrayList<String> estados = new ArrayList<>();
                            for (Paquete pack : tabla){
                                estados.add(pack.busquedaEstado(uidDescifrado, packIdDescifrado));

                            }
                            for (String estadoStr : estados){
                                if (!estadoStr.equals("")) estadoPaquete = estadoStr;
                            }
                            if (estadoPaquete.equals("")) estadoPaquete = "DESCONOCIDO";
                        }

                    System.out.println("15.e Estado encontrado: " +estadoPaquete);
                    estado = enviarEstadoCifrado(pOut, ivSpec, estadoPaquete); // Tambien se envia el HMAC del estado del paquete
                    } else {
                        estado = 0;
                        System.out.println("Error en el procesamiento de HMAC de uid");
                    }
                    break;          

                case 9:
                    if (inputLine.equalsIgnoreCase("TERMINAR")) {

                        estado= 11;
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
        // String ruta_openssl = System.getProperty("user.dir") + "\\lib\\OpenSSL-1.1.1h_win32\\openssl.exe";
        // Process process = Runtime.getRuntime().exec(ruta_openssl + " dhparam -text 1024");
        // Process p = new ProcessBuilder().inheritIO().command("command1").start();

        String executablePath = "lib\\OpenSSL-1.1.1h_win32\\openssl.exe"; // para jkvgjkbbkhl

        String[] command = { executablePath, "dhparam", "-text", "1024" };
        
        // Process process = Runtime.getRuntime().exec(command);
        Process process = new ProcessBuilder().command(command).redirectErrorStream(true).start();

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

        // Procesar el contenido de output para extraer P y G
        extraerP_G(output.toString());
    }


    private static void extraerP_G(String output) {
        // Expresión regular para extraer el valor de prime
        Pattern primePattern = Pattern.compile("prime:\\s+([0-9a-fA-F:\\s]+)");
        // Expresión regular para extraer el valor de generator
        Pattern generatorPattern = Pattern.compile("generator:\\s+(\\d+)");
    
        Matcher primeMatcher = primePattern.matcher(output);
        Matcher generatorMatcher = generatorPattern.matcher(output);
    
        if (primeMatcher.find() && generatorMatcher.find()) {
            // Obtener el valor hexadecimal de prime y quitar los : y espacios
            String primeHex = primeMatcher.group(1).replaceAll("[:\\s]", "");
            P = new BigInteger(primeHex, 16); // Convertir de hexadecimal a decimal
    
            // Obtener el valor de generator como decimal
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
            
            
            return 3; // Avanza al siguiente estado
        } catch (Exception e) {
            System.err.println("Error al generar los parámetros P, G y G^x: " + e.getMessage());
            e.printStackTrace();
            return 0; // Reinicia el protocolo en caso de error
        }
    }
    // Método para calcular las llaves simétricas K_AB1 y K_AB2
    private static void calcularLlavesSimetricas() {
        try {
            // Calcular la clave maestra (G^y)^x mod P
            BigInteger claveMaestra = gy.modPow(x, P);

            // Generar el digest SHA-512 de la clave maestra
            MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512Digest.digest(claveMaestra.toByteArray());

            // Dividir el digest en dos mitades para crear K_AB1 y K_AB2
            byte[] llave_pa_cifrar = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits para cifrado
            byte[] llave_pa_MAC = Arrays.copyOfRange(digest, 32, 64);   // Últimos 256 bits para HMAC

            // Crear llaves SecretKey para cifrado y MAC
            llaveSimetrica_cifrar = new SecretKeySpec(llave_pa_cifrar, "AES");
            llaveSimetrica_MAC = new SecretKeySpec(llave_pa_MAC, "AES");

            //System.out.println("Llave simétrica para cifrado (K_AB1): " + new BigInteger(1, llave_pa_cifrar).toString(16));
            //System.out.println("Llave simétrica para HMAC (K_AB2): " + new BigInteger(1, llave_pa_MAC).toString(16));

        } catch (Exception e) {
            System.err.println("Error al calcular las llaves simétricas: " + e.getMessage());
            e.printStackTrace();
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
        
        return ivSpec;
    }

    private static void enviarIV(PrintWriter pOut, IvParameterSpec ivSpec) {
        String ivBase64 = Base64.getEncoder().encodeToString(ivSpec.getIV());
        pOut.println(ivBase64); 
        System.out.println("12. IV enviado al cliente: " + ivBase64);
    }

    public static String descrifradoSimetricoId(String uidCifrado, SecretKey llaveCifrado, IvParameterSpec iv) {
        try {
            String uidDescifrado = Seguridad.descifradoSimetrico(uidCifrado, llaveCifrado, iv);
            //boolean verificacionHMAC = verificarHMacUid(uidDescifrado, llaveSimetrica_MAC, uidDescifrado);
            return uidDescifrado;
            
        } catch (Exception e) {
            System.err.println("Error al verificar el cifrado del UID: " + e.getMessage());
            e.printStackTrace();
            return "";
        }
    }
    
    public static boolean verificarHMacUid(String hmacRecibido, SecretKey llaveSimetrica_MAC, String uidEsperado) {
        try {
            String hmacCalculado = Seguridad.calcularHMAC(llaveSimetrica_MAC, uidEsperado);
            return hmacCalculado.equals(hmacRecibido);
        } catch (Exception e) {
            System.err.println("Error al verificar el HMAC del UID: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    

    private static int enviarEstadoCifrado(PrintWriter pOut, IvParameterSpec ivVectorIni, String estado) {
        try {
            String estadoCifrado = Seguridad.cifradoSimetrico(estado, llaveSimetrica_cifrar, ivVectorIni);
            System.out.println("Estado cifrado: " + estadoCifrado);
            System.out.println("16a. Enviar C(K_AB1, estado)");
            String hmac = enviarHmacEstado(pOut, estado);
            String mensajeCompleto = estadoCifrado + ";" + hmac;

            pOut.println(mensajeCompleto); // Enviar el estado cifrado + hmac estado al servidor
            return 9;
        
        } catch (Exception e) {
            System.err.println("Error al cifrar y enviar el estado: " + e.getMessage());
            e.printStackTrace();
            return 0; // Reinicia en caso de error        
      }
    }

    public static String enviarHmacEstado(PrintWriter pOut, String estado){
        try {
            String hmac = Seguridad.calcularHMAC(llaveSimetrica_MAC, estado);
            System.out.println("HMAC del estado: " + hmac);
            System.out.println("16b. Enviar HMAC(K_AB2, estado)");
            return hmac;

        } catch (Exception e) {
            System.err.println("Error al calcular y enviar el HMAC del UID: " + e.getMessage());
            e.printStackTrace();
            return ""; // Reinicia en caso de error        
      }
    }


}