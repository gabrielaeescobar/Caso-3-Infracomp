public class Paquete {
    private String id;
    private String uid;
    private int estado;
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

    

    

}
