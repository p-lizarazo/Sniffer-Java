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
public class IP4Packet {
    private int version; //
    private int headerlen; //
    private int codepoint; // Differentiated services codepoint
    private int ecnbits; //Explicit Congestion Notification
    private int length; //
    private int id; //
    private int reservedbit;
    private int donotfragment;
    private int morefragment;
    private int fragmentOffset;
    private int ttl;
    private int protocol;//Type protocol
    private int hchecksum;
    private String source;
    private String destination;
    private EthPacket eth;
    private ICMPacket icmp;

    public IP4Packet(int version, int headerlen, int codepoint, int ecnbits,
            int length, int id, int reservedbit, 
            int donotfragment, int morefragment, int fragmentOffset,
            int ttl, int protocol, int hchecksum, String source, 
            String destination,EthPacket eth) {
        this.version = version;
        this.headerlen = headerlen;
        this.codepoint = codepoint;
        this.ecnbits = ecnbits;
        this.length = length;
        this.id = id;
        this.reservedbit = reservedbit;
        this.donotfragment = donotfragment;
        this.morefragment = morefragment;
        this.fragmentOffset = fragmentOffset;
        this.ttl = ttl;
        this.protocol = protocol;
        this.hchecksum = hchecksum;
        this.source = source;
        this.destination = destination;
        this.eth=eth;
        
        constrIC();
    }
    
    private void constrIC(){
        int[] packetinfobyte=eth.getPacket().getPacketinfobyte();
            //34
        if(this.fragmentOffset==0 && this.protocol==1){
            
        
            int type = packetinfobyte[34];
            int code = packetinfobyte[35];
            int checksum = (packetinfobyte[36]<<8) | (packetinfobyte[37]);
            int idle =  (packetinfobyte[39]<<8) | (packetinfobyte[38]);
            int idbe = (packetinfobyte[38]<<8) | (packetinfobyte[39]);
            int secle = (packetinfobyte[41]<<8) | (packetinfobyte[40]);
            int secbe = (packetinfobyte[40]<<8) | (packetinfobyte[41]);
            // Data declare
            this.icmp=new ICMPacket(type,code,checksum,idle,idbe,secle,secbe);
        } else {
            this.icmp=null;
        }
        
        
    }

    @Override
    public String toString() {
        
        if(icmp==null)
            return "IP4Packet{" + "version=" + (int)version + ", headerlen=" + headerlen + ", codepoint=" + codepoint + ", ecnbits=" + ecnbits + 
                    ", length=" + length + ", id=" + id + ", reservedbit=" + (int)reservedbit + ", donotfragment=" + (int)donotfragment + ", morefragment=" 
                    + (int)morefragment + ", fragmentOffset=" + fragmentOffset + ", ttl=" + ttl + ", protocol=" + protocol + ",hchecksum " + hchecksum
                    + ", source=" + source + ", destination=" + destination + '}';
        else
            return "IP4Packet{" + "version=" + (int)version + ", headerlen=" + headerlen + ", codepoint=" + codepoint + ", ecnbits=" + ecnbits + 
                    ", length=" + length + ", id=" + id + ", reservedbit=" + (int)reservedbit + ", donotfragment=" + (int)donotfragment + ", morefragment=" 
                    + (int)morefragment + ", fragmentOffset=" + fragmentOffset + ", ttl=" + ttl + ", protocol=" + protocol + ",hchecksum=" + hchecksum
                    + ", source=" + source + ", destination=" + destination + ", ICMP="+ icmp.toString() +'}';
    }
    
    

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public int getHeaderlen() {
        return headerlen;
    }

    public void setHeaderlen(int headerlen) {
        this.headerlen = headerlen;
    }

    public int getCodepoint() {
        return codepoint;
    }

    public void setCodepoint(int codepoint) {
        this.codepoint = codepoint;
    }

    public int getEcnbits() {
        return ecnbits;
    }

    public void setEcnbits(int ecnbits) {
        this.ecnbits = ecnbits;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getReservedbit() {
        return reservedbit;
    }

    public void setReservedbit(int reservedbit) {
        this.reservedbit = reservedbit;
    }

    public int getDonotfragment() {
        return donotfragment;
    }

    public void setDonotfragment(int donotfragment) {
        this.donotfragment = donotfragment;
    }

    public int getMorefragment() {
        return morefragment;
    }

    public void setMorefragment(int morefragment) {
        this.morefragment = morefragment;
    }

    public int getFragmentOffset() {
        return fragmentOffset;
    }

    public void setFragmentOffset(int fragmentOffset) {
        this.fragmentOffset = fragmentOffset;
    }

    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public int getHchecksum() {
        return hchecksum;
    }

    public void setHchecksum(int hchecksum) {
        this.hchecksum = hchecksum;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getDestination() {
        return destination;
    }

    public void setDestination(String destination) {
        this.destination = destination;
    }

    public EthPacket getEth() {
        return eth;
    }

    public void setEth(EthPacket eth) {
        this.eth = eth;
    }

    public ICMPacket getIcmp() {
        return icmp;
    }

    public void setIcmp(ICMPacket icmp) {
        this.icmp = icmp;
    }
    
    
    
    
    
    
    
}
