/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;
import java.sql.Timestamp;
import java.util.Date;
import java.util.List;


/**
 *
 * @author Pedro
 */
public class Packet {
    private int number; //
    private Timestamp time; //
    private int wireLength; //
    private int capturedLength; //   
    private EthPacket eth; 
    private List<String> packetinfohex; //
    private int[] packetinfobyte; //
    
    
    public Packet(int wireLength,int number,int[] packetinfobyte,List<String> packetinfohex){
        this.wireLength=wireLength;
        this.capturedLength=wireLength;
        this.number=number;
        Date date = new Date();
        this.time = new Timestamp(date.getTime());
        this.packetinfobyte = packetinfobyte;
        this.packetinfohex = packetinfohex;
        constr(this.packetinfohex,this.packetinfobyte);
        
    }
    
    private void constr(List<String> packetinfohex, int[] packetinfobyte){
        String destination = new String("");
        for(int i=0;i<6;++i){
            if(i<5)
                destination = destination.concat(packetinfohex.get(i)+":");
            else
                destination = destination.concat(packetinfohex.get(i));
        }
        String source = new String("");
        for(int i=6;i<12;++i){
            if(i<11)
                source = source.concat(packetinfohex.get(i)+":");
            else
                source = source.concat(packetinfohex.get(i));
        }
        String type = new String("");
        for(int i=12;i<14;++i){
            type = type.concat(packetinfohex.get(i));
        }
        
        
        int lgbitD = Utils.isKthBitSet( packetinfobyte[0] , 2); //LG D
        int igbitD = Utils.isKthBitSet( packetinfobyte[0] , 1); //IG D
        int lgbitS = Utils.isKthBitSet( packetinfobyte[6] , 2); //LG S
        int igbitS = Utils.isKthBitSet( packetinfobyte[6] , 1); //IG S
        
        this.eth = new EthPacket(destination,source,type,
                        lgbitD,igbitD,lgbitS,igbitS, this );
    }

    public int getNumber() {
        return number;
    }

    public void setNumber(int number) {
        this.number = number;
    }

    public Timestamp getTime() {
        return time;
    }

    public void setTime(Timestamp time) {
        this.time = time;
    }

    public int getWireLength() {
        return wireLength;
    }

    public void setWireLength(int wireLength) {
        this.wireLength = wireLength;
    }

    public int getCapturedLength() {
        return capturedLength;
    }

    public void setCapturedLength(int capturedLength) {
        this.capturedLength = capturedLength;
    }

    public EthPacket getEth() {
        return eth;
    }

    public void setEth(EthPacket eth) {
        this.eth = eth;
    }

    public List<String> getPacketinfohex() {
        return packetinfohex;
    }

    public void setPacketinfohex(List<String> packetinfohex) {
        this.packetinfohex = packetinfohex;
    }

    public int[] getPacketinfobyte() {
        return packetinfobyte;
    }

    public void setPacketinfobyte(int[] packetinfobyte) {
        this.packetinfobyte = packetinfobyte;
    }

    @Override
    public String toString() {
        return "Packet{" + "number=" + number + ", time=" + time + ", wireLength=" + wireLength + ", capturedLength=" + 
                capturedLength + ", eth=" + eth.toString() +  '}';
    }
    
    
    
    
}
