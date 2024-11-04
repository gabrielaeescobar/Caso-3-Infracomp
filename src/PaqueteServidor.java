import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class PaqueteServidor {
    // Mapa principal: usuario -> (paquete -> estado)
    private Map<String, Map<String, String>> tablaPaquetes;
    private String[] estados = {"ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO", "ENENTREGA", "ENTREGADO", "DESCONOCIDO"};
    private static final Random random = new Random();
    public PaqueteServidor() {

        tablaPaquetes = new HashMap<>();
        for (int i =0;i<= 33;i++ ){
            agregarPaquete("user00"+i, "pk00"+i, estados[random.nextInt(estados.length)]);
        }
       
    }

    // Método para agregar un paquete a la estructura
    public void agregarPaquete(String login, String idPaquete, String estado) {
        // Si el usuario no existe en la tabla, lo inicializamos
        tablaPaquetes.putIfAbsent(login, new HashMap<>());
        // Agregamos el paquete y su estado
        tablaPaquetes.get(login).put(idPaquete, estado);
    }

    // Método para consultar el estado de un paquete
    public String consultarEstado(String login, String idPaquete) {
        // Verifica si el usuario y el paquete existen, de lo contrario devuelve "DESCONOCIDO"
        return tablaPaquetes.getOrDefault(login, new HashMap<>()).getOrDefault(idPaquete, "DESCONOCIDO");
    }

}
