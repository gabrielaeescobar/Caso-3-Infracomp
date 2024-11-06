import java.math.*;
import javax.crypto.spec.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.io.*;
import javax.crypto.*;

public class ProtocoloCliente {

    private PublicKey llavePublica;
    private BigInteger p,g,gx,gy,y;  // Secreto y del cliente
    private SecureRandom random = new SecureRandom();
    private SecretKey llaveSimetrica_cifrar; // Llave para cifrado
    private SecretKey llaveSimetrica_MAC;    // Llave para MAC
    private IvParameterSpec ivVectorIni; // vector que manda el servidor
    private final String rutaLlavePublica = "llave_publica.ser";
    private final String reto = generarRetoAleatorio(); 
    private String estadoDescifrado, hmacEstadoVerificado, retoCifrado;
            
    public void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, String uid, String paqueteid) throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        cargarLlavePublica();
        
        int estado = 1;
        boolean ejecutar = true;
        
        while (ejecutar) {
            switch (estado) {
                case 1 : 
                    estado = estadoInicial(stdIn, pIn, pOut);
                    break;
                case 2 : 
                    estado = enviarReto(pOut, pIn);
                    break;
                case 3 : 
                    estado = verificarFirmaServidor(pIn, pOut);
                    break;   
                case 4 : 
                    estado=calcularLlavesSimetricas();
                    System.out.println("11a. Calcula (G^x)^y");

                    pOut.println(gy.toString());
                    System.out.println("11. Enviar G^y");
                    break;   
                case 5 : 
                    ivVectorIni = recibirIV(pIn);
                    estado = enviarUidCifrado(pOut, ivVectorIni, uid); // Tambien se envia el HMAC del uid
                    break;                        
                 case 6 : 
                    estado = enviarPaqueteidCifrado(pOut, ivVectorIni, paqueteid); // Tambien se envia el HMAC del paqueteid
                     break;              
                 case 7 : 
                    estado = verificarFinal(pIn,pOut);
                    break;         
                case 8: 
                    estado = enviarTerminar(pOut, pIn);
                    break;         
                default : {
                    System.out.println("Protocolo terminado o error.");
                    ejecutar = false;
                }
            }
        }
    }

    private int estadoInicial(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException {
        System.out.println("1. Enviando SECINIT...");
        pOut.println("SECINIT");
        return 2; 
    }

    private int enviarReto(PrintWriter pOut, BufferedReader pIn) throws IOException {
        try {
            long inicioTiempo = System.currentTimeMillis(); // Inicio del cronómetro
            retoCifrado = Seguridad.cifradoAsimetrico(reto, llavePublica);
            long finTiempo = System.currentTimeMillis(); // Fin del cronómetro
            long tiempoEjecucion = finTiempo - inicioTiempo;
            System.out.println("2a. Cifrar reto");

            System.out.println("### Tiempo en cifrar el reto: " + tiempoEjecucion + " ms");


            pOut.println(retoCifrado); // Paso 2b: enviar el reto cifrado
            System.out.println("2b. Enviar reto cifrado");
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error al cifrar y enviar el reto.");
            return 1;
        }
        
        // Espera respuesta del servidor
        String fromServer = pIn.readLine();
        if (fromServer != null) {
            int estadoNuevo= verificarRta(fromServer, pIn, pOut);
            if (estadoNuevo!= 0){
                return estadoNuevo; // Avanza al siguiente estado de comando

            }
        }
        
        System.out.println("Error: Respuesta inesperada del servidor.");
        return 2;
    }

    private int verificarRta(String fromServer,BufferedReader pIn, PrintWriter pOut) throws IOException {
        
        if (fromServer != null && fromServer.equals(reto)) { // Verifica si Rta == Reto
            System.out.println("5. Verificación exitosa de Rta == Reto");
            pOut.println("OK"); // Enviar "OK" como confirmación
            System.out.println("6. Enviar OK");
            return 3;
        }
        
        System.out.println("6. Enviar ERROR");
        return 0;
    }

    private int verificarFirmaServidor(BufferedReader pIn, PrintWriter pOut) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        try {
            String fromServer = pIn.readLine();
            if (fromServer == null) {
                System.out.println("Error: No se recibió mensaje del servidor.");
                return 0;
            }        
            String[] partes = fromServer.split(";");
            p = new BigInteger(partes[0]);
            g = new BigInteger(partes[1]);
            gx = new BigInteger(partes[2]);
            String firmaBase64 = partes[3];
            String mensaje = p.toString() + ";" + g.toString() + ";" + gx.toString();
            byte[] mensajeBytes = mensaje.getBytes();
            byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64);
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(llavePublica);
            signature.update(mensajeBytes);
            boolean verificacion = signature.verify(firmaBytes);

            if (fromServer != null && verificacion) {
                System.out.println("9. Verifica Firma");
                pOut.println("OK"); // Enviar confirmación al servidor
                System.out.println("10. Envia OK.");
                return 4;
            } else {
                System.out.println("9. Verifica Firma");
                pOut.println("ERROR");
                System.out.println("10. Envia ERROR.");
                return 0;
            }
        }
        catch (Exception e) {
            System.err.println("Error al verificar la firma: " + e.getMessage());
            e.printStackTrace();
            return 0;
        }

    }
    
    private int enviarUidCifrado(PrintWriter pOut, IvParameterSpec ivVectorIni, String uid) {
        try {
            String uidCifrado = Seguridad.cifradoSimetrico(uid, llaveSimetrica_cifrar, ivVectorIni);
            System.out.println("UID cifrado: " + uidCifrado);
            pOut.println(uidCifrado); // Enviar el UID cifrado al servidor
            System.out.println("13a. Enviar C(K_AB1, uid)");

            return enviarHmacUid(pOut, uid);
        
        } catch (Exception e) {
            System.err.println("Error al cifrar y enviar el UID: " + e.getMessage());
            e.printStackTrace();
            return 0;   
      }
    }

    public int enviarHmacUid(PrintWriter pOut, String uid){
        try {
            String hmac = Seguridad.calcularHMAC(llaveSimetrica_MAC, uid);
            System.out.println("HMAC del UID: " + hmac);
            pOut.println(hmac);
            System.out.println("13b. Enviar HMAC(K_AB2, uid)");
            return 6;

        } catch (Exception e) {
            System.err.println("Error al calcular y enviar el HMAC del UID: " + e.getMessage());
            e.printStackTrace();
            return 0;
      }
    }

    private int enviarPaqueteidCifrado(PrintWriter pOut, IvParameterSpec ivVectorIni, String paqueteid) {
        try {
            String paqueteidCifrado = Seguridad.cifradoSimetrico(paqueteid, llaveSimetrica_cifrar, ivVectorIni);
            System.out.println("Paquete cifrado: " + paqueteidCifrado);
            System.out.println("14a. Enviar C(K_AB1, paqueteid)");
            pOut.println(paqueteidCifrado); // Enviar el paqueteid cifrado al servidor

            return enviarHmacPaqueteid(pOut, paqueteid);
        
        } catch (Exception e) {
            System.err.println("Error al cifrar y enviar el Paquete: " + e.getMessage());
            e.printStackTrace();
            return 0;  
      }
    }

    public int enviarHmacPaqueteid(PrintWriter pOut, String paqueteid){
        try {
            String hmac = Seguridad.calcularHMAC(llaveSimetrica_MAC, paqueteid);
            System.out.println("HMAC del Paquete: " + hmac);
            pOut.println(hmac);
            System.out.println("14b. Enviar HMAC(K_AB2, paqueteid)");
            return 7;

        } catch (Exception e) {
            System.err.println("Error al calcular y enviar el HMAC del Paquete: " + e.getMessage());
            e.printStackTrace();
            return 0; 
      }
    }

    private IvParameterSpec recibirIV(BufferedReader pIn) throws IOException {
        String ivBase64 = pIn.readLine(); // Recibe el IV 
        byte[] iv = Base64.getDecoder().decode(ivBase64); // Decodifica el IV
        return new IvParameterSpec(iv); // Crea el IvParameterSpec para usar en cifrado
    }

    // generar G^y
    private void generarGy() {
        if (p == null || g == null) {
            throw new IllegalStateException("Los valores de P y G deben ser inicializados antes de llamar a generarGx.");
        }
    
        // Generar un valor secreto y aleatorio en el rango [1, P-1] y calcular G^y mod P
        y = new BigInteger(1024, random).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE); // Guardamos el valor de y
        gy = g.modPow(y, p); // Calculamos G^x mod P
    }

    private int calcularLlavesSimetricas() {
        try {
            // Paso 1: Generar el valor secreto y del cliente
            generarGy();

            // Paso 2: Calcular la clave maestra (G^x)^y mod P
            BigInteger claveMaestra = gx.modPow(y, p);
            System.out.println("Clave maestra calculada (G^x)^y mod P: " + claveMaestra);

            // Paso 3: Generar el digest SHA-512 de la clave maestra
            MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512Digest.digest(claveMaestra.toByteArray());

            // Paso 4: Dividir el digest en dos mitades para crear K_AB1 y K_AB2
            byte[] llave_pa_cifrar = Arrays.copyOfRange(digest, 0, 32); // Primeros 256 bits para cifrado
            byte[] llave_pa_MAC = Arrays.copyOfRange(digest, 32, 64);   // Últimos 256 bits para HMAC

            // Crear llaves SecretKey para cifrado y MAC
            llaveSimetrica_cifrar = new SecretKeySpec(llave_pa_cifrar, "AES");
            llaveSimetrica_MAC = new SecretKeySpec(llave_pa_MAC, "AES");

            // Configurar el cifrador AES en modo CBC con PKCS5 Padding
            //cifradorAES = Cipher.getInstance("AES/CBC/PKCS5Padding");

            System.out.println("Llave simétrica para cifrado (K_AB1): " + new BigInteger(1, llave_pa_cifrar).toString(16));
            System.out.println("Llave simétrica para HMAC (K_AB2): " + new BigInteger(1, llave_pa_MAC).toString(16));

            return 5; // Avanza al siguiente estado
        } catch (Exception e) {
            System.err.println("Error al calcular las llaves simétricas: " + e.getMessage());
            e.printStackTrace();
            return 0; // Reinicia el protocolo en caso de error
        }
    }


    private void cargarLlavePublica() {
        llavePublica = (PublicKey) cargarLlaveDesdeArchivo(rutaLlavePublica);
        if (llavePublica != null) {
            System.out.println("0.b Llave pública cargada desde " + rutaLlavePublica);
        }
    }

    private Object cargarLlaveDesdeArchivo(String rutaArchivo) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(rutaArchivo))) {
            return ois.readObject();
        } catch (Exception e) {
            System.err.println("Error al cargar la llave desde " + rutaArchivo + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private String generarRetoAleatorio() {
        SecureRandom random = new SecureRandom();
        int numeroAleatorio = random.nextInt(90000) + 10000;
        return String.valueOf(numeroAleatorio);
    }
    
    public String descrifradoSimetricoEstado(String estado, SecretKey llaveCifrado, IvParameterSpec iv) {
        try {
            String estadoDescifrado = Seguridad.descifradoSimetrico(estado, llaveCifrado, iv);
            return estadoDescifrado;
            
        } catch (Exception e) {
            System.err.println("Error al verificar el cifrado del estado: " + e.getMessage());
            e.printStackTrace();
            return "";
        }
    }
    
    public boolean verificarHMacEstado(String hmacRecibido, SecretKey llaveSimetrica_MAC, String estadoEsperado) {
        try {
            String hmacCalculado = Seguridad.calcularHMAC(llaveSimetrica_MAC, estadoEsperado);
            System.out.println("HMAC CALCULADO"+hmacCalculado);
            System.out.println("HMAC RECIBIDO"+hmacRecibido);

            return hmacCalculado.equals(hmacRecibido);
        } catch (Exception e) {
            System.err.println("Error al verificar el HMAC del estado: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    public int verificarFinal(BufferedReader pIn, PrintWriter pOut){
        try {

            String fromServer = pIn.readLine();
            if (fromServer == null) {
                System.out.println("Error: No se recibió mensaje del servidor.");
                return 0;
            }        
            System.out.println("Mensaje recibido del servidor en verificarFinal: " + fromServer);
            String[] partes = fromServer.split(";");
            if (partes.length != 2) {
                System.out.println("Error: Formato incorrecto del mensaje recibido.");
                return 0;
            }
            String cifradoEstado = partes[0];
            String hmacEstado = partes[1];
            estadoDescifrado = descrifradoSimetricoEstado(cifradoEstado, llaveSimetrica_cifrar, ivVectorIni);
            System.out.println("17.a Descifrar estado"+estadoDescifrado);
            boolean hmacVerificado = verificarHMacEstado(hmacEstado, llaveSimetrica_MAC, estadoDescifrado);
            if (hmacVerificado)  {
                System.out.println("17.b Estado verificado");
                return 8;

            } else {
                System.out.println("No se pudo verificar");
                return 0;

            }

        } catch (Exception e) {
            System.err.println("Error al verificar estado y paquete ID: " + e.getMessage());
            e.printStackTrace();
            return 0;
        }
    }

    private int enviarTerminar(PrintWriter pOut, BufferedReader pIn)  {
        try {
            pOut.println("TERMINAR");
            System.out.println("18. Enviar TERMINAR");

            return 9; // Estado que indica que la comunicación ha finalizado exitosamente
        } catch (Exception e) {
            System.err.println("Error al enviar el mensaje TERMINAR: " + e.getMessage());
            e.printStackTrace();
            return 0;
        }
    }
}