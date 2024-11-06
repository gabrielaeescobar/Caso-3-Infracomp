import java.math.BigInteger;
import javax.crypto.spec.*;
import java.util.regex.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import java.io.*;


public class ProtocoloServidor {

    private PublicKey llavePublica;
    private PrivateKey llavePrivada;
    private BigInteger P,G,Gx,x,gy;
    private SecretKey llaveSimetrica_cifrar; // Llave para cifrado (K_AB1)
    private SecretKey llaveSimetrica_MAC;    // Llave para MAC (K_AB2)
    private IvParameterSpec ivSpec; // almacena el IV
    private String uid,uidDescifrado; 
    private boolean hmac1Verificado,hmac2Verificado;
    private String packIdDescifrado;
    private String estadoPaquete="";
    private double tiempoEjecucion1, tiempoEjecucion2, tiempoEjecucion3, tiempoEjecucionTot; 

    private final SecureRandom random = new SecureRandom();
    private final String rutaCarpetaServidor = "src/DatosServidor";
    private final String rutaLlavePrivada = rutaCarpetaServidor + "/llave_privada.ser"; 
    private final String rutaLlavePublica = "llave_publica.ser";

    public void procesar(BufferedReader pIn, PrintWriter pOut, ArrayList<Paquete> tabla) throws IOException {

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
                        double inicioTiempo = System.currentTimeMillis(); // Inicio del cronómetro

                        String rta = Seguridad.descifradoAsimetrico(inputLine, llavePrivada);

                        double finTiempo = System.currentTimeMillis(); // Fin del cronómetro
                        double tiempoEjecucion = finTiempo - inicioTiempo;
                        System.out.println("### Tiempo de descifrado: " + tiempoEjecucion + " ms");


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

                        double inicioTiempo = System.currentTimeMillis(); // Inicio del cronómetro
                        generarParametrosEImprimir(); // Generar P, G, y G^x
                        double finTiempo = System.currentTimeMillis(); // Fin del cronómetro
                        double tiempoEjecucion = finTiempo - inicioTiempo;
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
                    if (inputLine.equalsIgnoreCase("OK")) {
                        System.out.println("Cliente envió OK");
                        estado++; // va al siguiente estado para recibir G^y
                    } else if (inputLine.equalsIgnoreCase("ERROR")) {
                        System.out.println("Cliente envió ERROR");
                        estado = 0; 
                    } else {
                        System.out.println("Mensaje no esperado del cliente: " + inputLine);
                        estado = 0; 
                    }
                    break;

                case 4:
                    gy= new BigInteger(inputLine);
                     calcularLlavesSimetricas();
                    System.out.println("11b. Calcula (G^y)^x");

                    ivSpec = generarIV();
                    enviarIV(pOut, ivSpec);
                    estado++;

                    break;

                case 5: 
                    // Paso 15: Verificar UID y paquete_id con sus respectivos HMAC en un solo paso
                    try {
                        double inicioTiempo1 = System.currentTimeMillis(); // Inicio del cronómetro
                        uidDescifrado = descrifradoSimetricoId(inputLine, llaveSimetrica_cifrar, ivSpec);
                        System.out.println("15.a Descifrar uid");
                        estado++;
                        double finTiempo1 = System.currentTimeMillis(); // Fin del cronómetro
                        tiempoEjecucion1 = finTiempo1 - inicioTiempo1;

                    } catch (Exception e) {
                        System.err.println("Error al verificar UID y paquete ID: " + e.getMessage());
                        e.printStackTrace();
                        estado = 0;
                    }
                    break;

                case 6:
                    double inicioTiempo2 = System.currentTimeMillis(); // Inicio del cronómetro

                    hmac1Verificado= verificarHMacUid(inputLine, llaveSimetrica_MAC, uidDescifrado);
                    if (hmac1Verificado){
                        estado++;
                        System.out.println("15.b HMAC uid verificado");
                        double finTiempo2 = System.currentTimeMillis(); // Fin del cronómetro
                        tiempoEjecucion2 = finTiempo2 - inicioTiempo2;


                    } else {
                        estado = 0;
                        System.out.println("Error en el procesamiento de HMAC de uid");
                    }
                    break;
                case 7:
                    double inicioTiempo3 = System.currentTimeMillis(); // Inicio del cronómetro

                    packIdDescifrado = descrifradoSimetricoId(inputLine, llaveSimetrica_cifrar, ivSpec);
                    System.out.println("15.c Descifrar packid");
                    estado++;
                    double finTiempo3 = System.currentTimeMillis(); // Fin del cronómetro
                    tiempoEjecucion3 = finTiempo3 - inicioTiempo3;
                    break;

                case 8:
                    double inicioTiempo4 = System.currentTimeMillis(); // Inicio del cronómetro

                    hmac2Verificado= verificarHMacUid(inputLine, llaveSimetrica_MAC, packIdDescifrado);
                    if (hmac2Verificado){
                        estado++;
                        System.out.println("15.d HMAC packid verificado");
                        double finTiempo4 = System.currentTimeMillis(); // Fin del cronómetro
                        tiempoEjecucionTot = (finTiempo4 - inicioTiempo4)+tiempoEjecucion1+tiempoEjecucion2+tiempoEjecucion3;
                        // System.out.println("### tiempo 1: "+ tiempoEjecucion1);
                        // System.out.println("### tiempo 2: "+ tiempoEjecucion2);
                        // System.out.println("### tiempo 3: "+ tiempoEjecucion3);

                        System.out.println("### Tiempo en ejecutar el paso 15: " + tiempoEjecucionTot + " ms");;
    
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

    public   void generarP_G() throws Exception {

        String executablePath = "lib\\OpenSSL-1.1.1h_win32\\openssl.exe"; // para jkvgjkbbkhl

        String[] command = { executablePath, "dhparam", "-text", "1024" };
        
        Process process = new ProcessBuilder().command(command).redirectErrorStream(true).start();

        // lee la salida del comando y acumularla en un StringBuilder
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            reader.lines().forEach(line -> output.append(line).append("\n"));
        }

        // espera a que el proceso termine
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Error al ejecutar OpenSSL. Código de salida: " + exitCode);
        }

        // procesa el contenido de output para extraer P y G
        extraerP_G(output.toString());
    }


    private   void extraerP_G(String output) {
        // exp regular para extraer el valor de prime
        Pattern primePattern = Pattern.compile("prime:\\s+([0-9a-fA-F:\\s]+)");
        // exp regular para extraer el valor de generator
        Pattern generatorPattern = Pattern.compile("generator:\\s+(\\d+)");
    
        Matcher primeMatcher = primePattern.matcher(output);
        Matcher generatorMatcher = generatorPattern.matcher(output);
    
        if (primeMatcher.find() && generatorMatcher.find()) {
            // el valor hexadecimal de prime y quitar los : y espacios
            String primeHex = primeMatcher.group(1).replaceAll("[:\\s]", "");
            P = new BigInteger(primeHex, 16); // Convertir de hexadecimal a decimal
    
            // el valor de generator como decimal
            G = new BigInteger(generatorMatcher.group(1));
        } else {
            throw new RuntimeException("No se pudo encontrar el valor de P o G en la salida de OpenSSL.");
        }
    }

   // para generar G^x
    private   void generarGx() {
        if (P == null || G == null) {
            throw new IllegalStateException("Los valores de P y G deben ser inicializados antes de llamar a generarGx.");
        }

        // hace un valor secreto x aleatorio en el rango [1, P-1] y calcula G^x mod P
        x = new BigInteger(1024, random).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE); // Guardamos el valor de x
        Gx = G.modPow(x, P); // Calculamos G^x mod P
    }

    // genera parámetros P, G y G^x y los imprime
    private   int generarParametrosEImprimir() {
        try {
            // los valores de P y G
            generarP_G();
            
            // calcula G^x
            generarGx();

            System.out.println("7. Genera G, P, G^X");
            
            
            return 3; 
        } catch (Exception e) {
            System.err.println("Error al generar los parámetros P, G y G^x: " + e.getMessage());
            e.printStackTrace();
            return 0;
        }
    }
    // para calcular las llaves simétricas K_AB1 y K_AB2
    private   void calcularLlavesSimetricas() {
        try {
            //clave maestra (G^y)^x mod P
            BigInteger claveMaestra = gy.modPow(x, P);

            // digest SHA-512 de la clave maestra
            MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512Digest.digest(claveMaestra.toByteArray());

            // divide el digest en dos mitades para crear K_AB1 y K_AB2
            byte[] llave_pa_cifrar = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits para cifrado
            byte[] llave_pa_MAC = Arrays.copyOfRange(digest, 32, 64);   // Últimos 256 bits para HMAC

            // crea llaves SecretKey para cifrado y MAC
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
    public   void cargarLlavePublica() {
        llavePublica = (PublicKey) cargarLlaveDesdeArchivo(rutaLlavePublica);
        if (llavePublica != null) {
            System.out.println("0.a Llave pública cargada desde " + rutaLlavePublica);
        }
    }

    //  cargar la llave privada desde el archivo
    public   void cargarLlavePrivada() {
        llavePrivada = (PrivateKey) cargarLlaveDesdeArchivo(rutaLlavePrivada);
        if (llavePrivada != null) {
            System.out.println("0.a Llave privada cargada desde " + rutaLlavePrivada);
        }
    }


    private   Object cargarLlaveDesdeArchivo(String rutaArchivo) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(rutaArchivo))) {
            return ois.readObject();
        } catch (Exception e) {
            System.err.println("Error al cargar la llave desde " + rutaArchivo + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }


    private   IvParameterSpec generarIV() {
        byte[] iv = new byte[16]; // IV de 16 bytes
        random.nextBytes(iv); // Genera un IV aleatorio
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        // code el IV en Base64 para enviarlo como texto
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        
        return ivSpec;
    }

    private   void enviarIV(PrintWriter pOut, IvParameterSpec ivSpec) {
        String ivBase64 = Base64.getEncoder().encodeToString(ivSpec.getIV());
        pOut.println(ivBase64); 
        System.out.println("12. IV enviado al cliente: " + ivBase64);
    }

    public   String descrifradoSimetricoId(String uidCifrado, SecretKey llaveCifrado, IvParameterSpec iv) {
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
    
    public   boolean verificarHMacUid(String hmacRecibido, SecretKey llaveSimetrica_MAC, String uidEsperado) {
        try {
            String hmacCalculado = Seguridad.calcularHMAC(llaveSimetrica_MAC, uidEsperado);
            return hmacCalculado.equals(hmacRecibido);
        } catch (Exception e) {
            System.err.println("Error al verificar el HMAC del UID: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    

    private   int enviarEstadoCifrado(PrintWriter pOut, IvParameterSpec ivVectorIni, String estado) {
        try {
            double inicioTiempo = System.currentTimeMillis(); // Inicio del cronómetro
            String estadoCifrado = Seguridad.cifradoSimetrico(estado, llaveSimetrica_cifrar, ivVectorIni);
            double finTiempo = System.currentTimeMillis(); // Fin del cronómetro
            double tiempoEjecucion = finTiempo - inicioTiempo;
            System.out.println("Estado cifrado: " + estadoCifrado);
            System.out.println("16a. Enviar C(K_AB1, estado)");
            System.out.println("### Tiempo en cifrar el estado (SIMETRICO): " + tiempoEjecucion + " ms");

            double inicioTiempoAsim = System.currentTimeMillis(); // Inicio del cronómetro
            String estadoCifradoAsim = Seguridad.cifradoAsimetrico(estadoCifrado, llavePublica);
            double finTiempoAsim = System.currentTimeMillis(); // Fin del cronómetro
            double tiempoEjecucionAsim = finTiempoAsim - inicioTiempoAsim;
            System.out.println("### Tiempo en cifrar el estado (ASIMETRICO): " + tiempoEjecucionAsim + " ms");

            String hmac = enviarHmacEstado(pOut, estado);
            String mensajeCompleto = estadoCifrado + ";" + hmac;

            pOut.println(mensajeCompleto); // manda el estado cifrado + hmac estado al servidor
            return 9;
        
        } catch (Exception e) {
            System.err.println("Error al cifrar y enviar el estado: " + e.getMessage());
            e.printStackTrace();
            return 0; 
      }
    }

    public   String enviarHmacEstado(PrintWriter pOut, String estado){
        try {
            String hmac = Seguridad.calcularHMAC(llaveSimetrica_MAC, estado);
            System.out.println("HMAC del estado: " + hmac);
            System.out.println("16b. Enviar HMAC(K_AB2, estado)");
            return hmac;

        } catch (Exception e) {
            System.err.println("Error al calcular y enviar el HMAC del UID: " + e.getMessage());
            e.printStackTrace();
            return ""; 
      }
    }


}