/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.util.Scanner;
import java.util.StringTokenizer;

/**
 *
 * @author Pedro
 */
public class Utils {
    /*
    private static int i = 0;
    public static Packet parse(String p){
        Packet pack;
        
        
        
        pack = new Packet(); // ....
        return pack;
    };
    
     public static Packet parse2(String p){
        
        if(i==0){
            Packet pack;
            
            String[] tokens = p.trim().split("\n");
            
            String[] tokens1 = tokens[1].split(" ");
            for(String token : tokens){
                System.out.println("tok: " + token);
            }
            
            
            Scanner scanner = new Scanner(p);
            
            scanner.useDelimiter("\\n");
            
            while( scanner.hasNext() ){
                System.out.println("toke: " + scanner.next().replaceAll("\\s+","")  );
            }
            // \[.*?\]
            pack = new Packet(); // ....
            i++;
            
            return pack;
        
        } else {
            return null;
        }
        
    };
    */
     
    public static int unsignedToBytes(byte b) {
        return b & 0xFF;
    }
    
    public static String byteTobits(byte b){
        return String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
    }
    
    public static byte isKthBitSet(byte n, int k) 
    { 
        byte i = (byte) (1 << (k-1));
        i&=n;
        return i;
    }

    /**
     *
     * @param n
     * @param k
     * @return
     */
    public static int isKthBitSet(int n, int k) 
    { 
        int i = (1 << (k-1));
        i&=n;
        return i;
    }
    
    public static String StringUnsignedByte(byte b) {
        int unsignedByte = b & 0xFF;
        return Integer.toString(unsignedByte); // "200"
    }
    
    public static String arrayintToString(int[] x){
        String s = new String("");
        for(int i=0;i<x.length;++i){
            s += (char)x[i] + " ";
        }
        
        return s;
    }
}
