/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import sniffer.Packet;
import sniffer.Utils;

/**
 *
 * @author Pedro
 */
public class Sniffer {
    /*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */


    
    public static void main(String[] args) {
       /* try{
            System.load("C:\\Users\\Pedro\\Downloads\\jnetpcap.dll");

       } catch(Exception e){

             e.printStackTrace();
       }
        */
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
        StringBuilder errbuf = new StringBuilder(); // For any error msgs

	if (Pcap.findAllDevs(alldevs, errbuf) != Pcap.OK) {
		throw new IllegalStateException(errbuf.toString());
	}

	System.out.println("Devices: " + alldevs.size()+ "  " + alldevs);
        
        
        
        Pcap pcap =
			Pcap.openLive(alldevs.get(0).getName(),
					Pcap.DEFAULT_SNAPLEN,
					Pcap.DEFAULT_PROMISC,
					Pcap.DEFAULT_TIMEOUT,
					errbuf);
	if (pcap == null) {
		throw new IllegalArgumentException(errbuf.toString());
	}
        
        List<Packet> pkt_list = new ArrayList<Packet>();
        
        PcapPacketHandler<String> jpacketHandler1 = new PcapPacketHandler<String>() { 

            private final Ethernet eth = new Ethernet(); // Preallocate our ethernet header
            private final Ip4 ip = new Ip4(); // Preallocat IP version 4 header
            private final Icmp icmp = new Icmp();
            
            @Override
            public void nextPacket(PcapPacket packet, String user) {  
                if (packet.hasHeader(icmp)  ) {
                    //System.out.println(packet.toString());
                    //Packet p = Utils.parse2(packet.toString());     
                    //pkt_list.add(p);
                    int num = packet.getPacketWirelen();
                    byte[] bytes = packet.getByteArray(0,packet.size());
                    
                    int [] array = new int[bytes.length];
                    
                   for(int i=0;i<array.length;++i){
                       array[i]=Utils.unsignedToBytes(bytes[i]);
                   }
                    List<String> hex = new ArrayList<String>();
                    /*
                    for(int i=0;i<packet.size();++i){
                        
                        String stemp = Integer.toHexString(array[i]);
                        if(stemp.length()==1) stemp = "0".concat(stemp);
                        if(i%16==0 && i!=0) System.out.println("");
                        System.out.print( stemp + " " );
                        hex.add(stemp);
                        
                    }
                    
                    System.out.println("");
                    */
                    Packet p = new Packet(num, (int) packet.getFrameNumber(),array,hex );
                    System.out.println(p.toString());
                }
           }
        };
        
        pcap.loop(Pcap.LOOP_INFINITE,jpacketHandler1, "");        
        pcap.close();
      

     

}

    
    
}
