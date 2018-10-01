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
public class EthPacket {
    private String destination;
    private String source;
    private String type;
    private int lgbitD;
    private int igbitD;
    private int lgbitS;
    private int igbitS;
    private IP4Packet ip4;
    private final Packet packet;
    
    public EthPacket(String destination,String source, String type,
                        int lgbitD, int igbitD,int lgbitS,int igbitS,
                        Packet packet)
    {
        this.destination=destination;
        this.source=source;
        this.type=type;
        this.lgbitD=lgbitD;
        this.igbitD=igbitD;
        this.lgbitS=lgbitS;
        this.igbitS=igbitS;
        this.packet=packet;
        constrip4();
        
    }
    
    private void constrip4(){
        
        int[] packetinfobyte=this.packet.getPacketinfobyte();
        //14
        
        int version; //4 bits
        int headerlen; //x*4
        
        int b = packetinfobyte[14];
        version = (b >> 4);
        headerlen = (b&15);
        b = packetinfobyte[15];
        int codepoint =  (b >> 2);
        b = packetinfobyte[15];
        int ecnbits = (b&3);
        
        int length = (packetinfobyte[16] << 4) | (packetinfobyte[17]);
        
        int id = (packetinfobyte[18]  << 8 ) | (packetinfobyte[19]);
        int reservedbit = Utils.isKthBitSet(packetinfobyte[20], 8);
        int donotfragment = Utils.isKthBitSet(packetinfobyte[20], 7);
        int morefragment = Utils.isKthBitSet(packetinfobyte[20], 6);
        b = packetinfobyte[20];
        b = (b&31);
        int fragmentOffset = (int)b;
        fragmentOffset = (fragmentOffset<<4) | (int)(packetinfobyte[21]);
        int ttl = packetinfobyte[22];
        int protocol = packetinfobyte[23];
        int hchecksum = (packetinfobyte[24]<<4) | (packetinfobyte[25]);
        String source = new String("");
        String destination = new String("");
        for(int i=0;i<4;++i){
            int x = packetinfobyte[26+i];
            if(i<3) source=source.concat( Integer.toString(x) + "." );
            else source=source.concat( Integer.toString(x) );
        }
        for(int i=0;i<4;++i){
            int x = packetinfobyte[30+i];
            if(i<3) destination=destination.concat( Integer.toString(x) + "." );
            else destination=destination.concat( Integer.toString(x) );
        }
        
        this.ip4 = new IP4Packet(version,headerlen,codepoint,ecnbits,length,id,
                        reservedbit,donotfragment,morefragment,fragmentOffset,ttl,
                        protocol,hchecksum, source, destination, this);
        return;
    }
    
    public Packet getPacket() {
        return packet;
    }
    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public int getLgbitD() {
        return lgbitD;
    }

    public void setLgbitD(int lgbitD) {
        this.lgbitD = lgbitD;
    }

    public int getIgbitD() {
        return igbitD;
    }

    public void setIgbitD(int igbitD) {
        this.igbitD = igbitD;
    }

    public int getLgbitS() {
        return lgbitS;
    }

    public void setLgbitS(int lgbitS) {
        this.lgbitS = lgbitS;
    }

    public int getIgbitS() {
        return igbitS;
    }
    public IP4Packet getIp4(){
        return ip4;
    }

    public void setIgbitS(int igbitS) {
        this.igbitS = igbitS;
    }

    @Override
    public String toString() {
        return "EthPacket{" + "destination=" + destination + ", source=" + source + ", type=" + type + ", lgbitD=" + lgbitD + ", igbitD=" + igbitD + ", lgbitS=" + lgbitS + ", igbitS=" + igbitS + ", ip4=" + ip4.toString() + '}';
    }

    

    /**
     *
     * @return
     */
    
    
    
    
}
