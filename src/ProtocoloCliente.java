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

            //si lo q ingresa el usuario no es null, y es diferente de "-1"
            // if (fromUser != null && !fromUser.equals("-1"))
            if (fromUser!= null){
                System.out.println("El usuario escribio: "+ fromUser);
                // si lo que ingtresa el usuario es "OK"
                if (fromUser.equalsIgnoreCase("OK")){
                    ejecutar = false;
                }

                //envia por la red
                pOut.println(fromUser);

            }
            // lee lo q llega por la red
            // si lo que llega del servidor no es null
            // observe la asignacion luego de la condicion
            if ((fromServer = pIn.readLine())!= null){
                System.out.println("Respuesta del Servidor: " + fromServer);
            }
        }
    }

}
