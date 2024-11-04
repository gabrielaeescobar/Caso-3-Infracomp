import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;

public class ProtocoloCliente {
    public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut) throws IOException{
        String fromServer;
        String fromUser;

        boolean ejecutar = true;

        while (ejecutar){
            //lee del teclado
            System.out.println("Escriba el msj para enviar: ");
            fromUser = stdIn.readLine();


            if (fromUser != null && !fromUser.equals("-1")) {
                System.out.println("El usuario escribió: " + fromUser);
                
                // si lo que ingresa el usuario es "OK"
                if (fromUser.equalsIgnoreCase("OK")) {
                    ejecutar = false;
                }

                //envia por la red
                pOut.println(fromUser);

            }
            else System.out.println("No fue valida la entrada");
            // lee lo q llega por la red
            // si lo que llega del servidor no es null
            // observe la asignacion luego de la condicion
            if ((fromServer = pIn.readLine())!= null){
                System.out.println("Respuesta del Servidor: " + fromServer);
            }
        }
    }

}
