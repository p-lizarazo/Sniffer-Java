/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

/**
 *
 * @author Pedro
 */
public class ICMPacket {
    private int type;
    private int code;
    private int checksum;
    private int idle;
    private int idbe;
    private int seqle;
    private int seqbe;
    
    public ICMPacket(int type, int code, int checksum, int idle, int idbe, int seqle, int seqbe) {
        this.type = type;
        this.code = code;
        this.checksum = checksum;
        this.idle = idle;
        this.idbe = idbe;
        this.seqle = seqle;
        this.seqbe = seqbe;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public int getChecksum() {
        return checksum;
    }

    public void setChecksum(int checksum) {
        this.checksum = checksum;
    }

    public int getIdle() {
        return idle;
    }

    public void setIdle(int idle) {
        this.idle = idle;
    }

    public int getIdbe() {
        return idbe;
    }

    public void setIdbe(int idbe) {
        this.idbe = idbe;
    }

    public int getSeqle() {
        return seqle;
    }

    public void setSeqle(int seqle) {
        this.seqle = seqle;
    }

    public int getSeqbe() {
        return seqbe;
    }

    public void setSeqbe(int seqbe) {
        this.seqbe = seqbe;
    }

    @Override
    public String toString() {
        return "ICMPacket{" + "type=" + type + ", code=" + code + ", checksum=" + checksum + ", idle=" + idle + ", idbe=" + idbe + ", seqle=" + seqle + ", seqbe=" + seqbe + '}';
    }
    
    
    
    
    
    
    
    
}
