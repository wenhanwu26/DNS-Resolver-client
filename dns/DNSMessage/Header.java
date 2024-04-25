package DNSMessage;

import java.nio.ByteBuffer;
import java.util.Random;

public class Header {
    String ID;

    String queryParameter;
    boolean AA;
    boolean RCODE; //has error or not //true mean has error


    String QDCOUNT;
    String ANCOUNT;
    String NSCOUNT;
    String ARCOUNT;


    public static Header getResponseHeader( byte[] bytes){
        Header h = new Header();
//        byte[] bytes = new byte[byteBuffer.remaining()];
//        byteBuffer.get(bytes, 0, bytes.length);


        String respond = DNSMessage.bytesToHex(bytes);

        h.ID = respond.substring(0,4); //0 1 2 3 hex
        h.queryParameter = respond.substring(4,8); //4 5 6 7 hex

        String queryParameterBinary = hexToBinary(h.queryParameter);

        h.AA = queryParameterBinary.charAt(5) == '1';
        h.RCODE = !(queryParameterBinary.substring(12,16).equals("0000"));


        h.QDCOUNT = respond.substring(8,12);
        h.ANCOUNT = respond.substring(12,16);
        h.NSCOUNT = respond.substring(16,20);
        h.ARCOUNT = respond.substring(20,24);

        return h;

    }
    public static Header getQueryHeader(){
        Header h = new Header();
        h.ID = generateID();
        h.queryParameter = "0000";
        h.QDCOUNT = "0001";
        h.ANCOUNT = "0000";
        h.NSCOUNT = "0000";
        h.ARCOUNT = "0000";
        return h;
    }


    public boolean isAA() {
        return AA;
    }

    public boolean isRCODE() {
        return RCODE;
    }

    public String getID() {
        return ID;
    }

    public String getQueryParameter() {
        return queryParameter;
    }

    public String getQDCOUNT() {
        return QDCOUNT;
    }

    public String getANCOUNT() {
        return ANCOUNT;
    }

    public String getNSCOUNT() {
        return NSCOUNT;
    }

    public String getARCOUNT() {
        return ARCOUNT;
    }

    public static String generateID(){
        String ID = "";
        Random r = new Random();
        int num = r.nextInt(65536);
        //System.out.println(num);
        ID = Integer.toHexString(num);
        while(ID.length()<4){
            ID = "0" +ID;
        }
        return ID;
    }

    public static String hexToBinary(String hex) {
        int i = Integer.parseInt(hex, 16);
        String bin = Integer.toBinaryString(i);
        return bin;
    }

    @Override
    public String toString() {
        return ID+queryParameter+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT;
    }
}
