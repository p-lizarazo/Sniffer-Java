/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer;

import java.util.List;

/**
 *
 * @author Pedro
 */
public class Data {
    
    private int [] payloadbytes;
    private List<String> payloadhex;
    private int length;
    private int padding;

    public Data(int[] payloadbytes, List<String> paylodhex, int length,int padding) {
        this.payloadbytes = payloadbytes;
        this.payloadhex = paylodhex;
        this.length = length;
        this.padding = padding;
    }

    public int getPadding() {
        return padding;
    }

    public void setPadding(int padding) {
        this.padding = padding;
    }

    public int[] getPayloadbytes() {
        return payloadbytes;
    }

    public void setPayloadbytes(int[] payloadbytes) {
        this.payloadbytes = payloadbytes;
    }

    public List<String> getPayloadhex() {
        return payloadhex;
    }

    public void setPayloadhex(List<String> payloadhex) {
        this.payloadhex = payloadhex;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    @Override
    public String toString() {
        return "Data{" + "payloadbytes=" + Utils.arrayintToString(payloadbytes) + ", payloadhex=" + payloadhex + ", length=" + length + ", padding=" + padding+'}';
    }
    
    
    
    
    
}
