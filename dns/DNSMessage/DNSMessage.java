package DNSMessage;

import dns.DNSNode;
import dns.RecordType;

public class DNSMessage {

    public static byte[] getQueryMessage(DNSNode n){
        String message = Header.getQueryHeader().toString()+Question.getQueryQuestion(n).toString();
        return (hexStringToByteArray(message));
    }




    //https://stackoverflow.com/questions/140131/convert-a-string-representation-of-a-hex-dump-to-a-byte-array-using-java
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    //https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static int hexStringtoSingedInt(String hex){
        return Integer.parseInt(hex, 16);
    }

    //hex should begin with the whole "Name" section represent in hex (REVISED: should be the whole message received)
    //startIndex = index (in hex) begin with Name section in each RR
    //nameSectionStartFrom = index represent where the Name section start in each RR (no used?)
    //endIndex exclusive (where the current Name section end)
    public static String decodeADomainName(String hex, int startIndex, int[] endIndex){
        String domainName = "";
        int count = 0;
        String oneByte = "";
        do{

            oneByte = hex.substring(startIndex+count,startIndex+count+2);

            if(isCompression(oneByte)){
                String twoByte = hex.substring(startIndex+count,startIndex+count+4);
                domainName += decodeCompression(hex,twoByte);
                count+= 4;
                endIndex[0] = startIndex+count;
                return domainName; //once encounter pointer, return the result
            }else{
                int numOfWords = Integer.parseUnsignedInt(oneByte,16);
                count += 2;
                do{
                    oneByte = hex.substring(startIndex+count,startIndex+count+2);
                    domainName += hexToWord(oneByte);
                    count += 2;
                    numOfWords--;
                }while(numOfWords>0);
                //count += 2;
            }
            oneByte = hex.substring(startIndex+count,startIndex+count+2); //test if next one is 00
            if(oneByte.equals("00")){//test if next one is 00, if yes increment count then return.
                count += 2;
                break;
            }
            domainName+=".";
        }while (!oneByte.equals("00"));
        //endIndex = new int[1];
        endIndex[0] = startIndex+count;
        return domainName;
    }

    public static RecordType decodeRecordType(String hex, int startIndex, int[] endIndex){
        int code = Integer.parseInt(hex.substring(startIndex,startIndex+4),16);
        endIndex[0] = startIndex+4;
        return RecordType.getByCode(code);
    }

    public static String decodeAType(String hex,int startIndex, int[]endIndex){
        endIndex[0]+=8;
        int first = Integer.parseInt(hex.substring(startIndex,startIndex+2),16);
        int second = Integer.parseInt(hex.substring(startIndex+2,startIndex+4),16);
        int third = Integer.parseInt(hex.substring(startIndex+4,startIndex+6),16);
        int fourth = Integer.parseInt(hex.substring(startIndex+6,startIndex+8),16);

        return first+"."+second+"."+third+"."+fourth;
    }

    public static String decodeAAAAType(String hex,int startIndex, int[]endIndex){
        endIndex[0]+=32;
        String first = Integer.toHexString(Integer.parseInt(hex.substring(startIndex,startIndex+4),16));
        String second = Integer.toHexString(Integer.parseInt(hex.substring(startIndex+4,startIndex+8),16));
        String third = Integer.toHexString(Integer.parseInt(hex.substring(startIndex+8,startIndex+12),16));
        String fourth = Integer.toHexString(Integer.parseInt(hex.substring(startIndex+12,startIndex+16),16));
        String five = Integer.toHexString(Integer.parseInt(hex.substring(startIndex+16,startIndex+20),16));
        String six = Integer.toHexString(Integer.parseInt(hex.substring(startIndex+20,startIndex+24),16));
        String seven = Integer.toHexString(Integer.parseInt(hex.substring(startIndex+24,startIndex+28),16));
        String eight = Integer.toHexString(Integer.parseInt(hex.substring(startIndex+28,startIndex+32),16));

        return first+":"+second+":"+third+":"+fourth+":"+five+":"+six+":"+seven+":"+eight;
    }


    public static String decodeNSType(String hex,int startIndex,int numOfbytes, int[]endIndex){
        int numOfHex = numOfbytes*2;
        String NS = decodeADomainName(hex,startIndex,new int[1]);
        endIndex[0] += numOfHex;
        return NS;
    }
    //https://stackoverflow.com/questions/9354860/how-to-get-the-value-of-a-bit-at-a-certain-position-from-a-byte
    public static boolean isCompression(String hex){
        byte[] label = hexStringToByteArray(hex);
        return getBit(6,label[0])==1 && getBit(7,label[0])==1;
    }
    public static byte getBit(int position, byte b)
    {
        return (byte) ((b >> position) & 1);
    }
    public static String decodeCompression(String hex,String twoByte){
//        twoByte = hexToBinary(twoByte);
//        Integer unsignedInt = Integer.parseUnsignedInt(Integer.parseInt(twoByte.substring(2),2)+"");
        String offsetBin = hexToBinary(twoByte).substring(2,8)+hexToBinary(twoByte).substring(8); //TODO test it
        //System.out.println("offset: "+offsetBin);
        int offset = Integer.parseUnsignedInt(offsetBin, 2); //offset
        //System.out.println("decimal: "+offset);

        int hexOffset = offset*2;
        return decodeADomainName(hex,hexOffset,new int[1]);
        //endIndex is not meainingful in compress message, endIndex is help us separate different domain name, not each label
        //know where are we in the Name section
    }
    public static String hexToWord(String hex){
        int yourInt = Integer.parseInt(hex,16);
        char ch = (char) yourInt;
        return ch+"";
    }

    //https://stackoverflow.com/questions/8640803/convert-hex-string-to-binary-string
    public static String hexToBinary(String hex) {
        int i = Integer.parseInt(hex, 16);
        String bin = Integer.toBinaryString(i);
        return bin;
    }


}
