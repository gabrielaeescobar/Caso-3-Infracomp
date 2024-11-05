public class Paquete {
    private String id;
    private String uid;
    private int estado;
    int[] estadosnum = {0, 1, 2, 3, 4, 5, 6};
    String[] estados = {"ENOFICINA", "RECOGIDO", "ENCLASIFICACION", "DESPACHADO", "ENENTREGA", "ENTREGADO", "DESCONOCIDO"};

    public Paquete(String id, String uid, int estado) {
        this.id = id;
        this.uid = uid;
        this.estado = estado;
    }
    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }
    public String getUid() {
        return uid;
    }
    public void setUid(String uid) {
        this.uid = uid;
    }
    public int getEstado() {
        return estado;
    }
    public void setEstado(int estado) {
        this.estado = estado;
    }

    public String busquedaEstado(String uId, String packId){
        if (uid.equals(uId) && id.equals(packId)){
            return estados[this.estado];
        }
        else return "";
    }

    public String getEstadoReal(int estadoNum){
        return estados[estadoNum];
    }



    

    

}
