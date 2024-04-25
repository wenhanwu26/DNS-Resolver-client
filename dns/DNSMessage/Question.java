package DNSMessage;

import dns.DNSNode;

public class Question {
    String QNAME;
    String QTYPE;
    String QCLASS;

    //get DNS node to know host name and reocrd type

    public static Question getQueryQuestion(DNSNode n){
        Question q = new Question();
        q.QNAME = getQName(n);
        q.QTYPE = getQType(n);
        q.QCLASS = "0001";
        return q;
    }

    public static String getQName(DNSNode n){
        String[] hostName = n.getHostName().trim().split("\\.");
        String QName = "";
        for(String str:hostName){
            str = str.toLowerCase();
            int number = str.length();
            QName += numToHex(number);
            for(int i = 0;i<str.length();i++){
                QName += ""+numToHex((int)str.charAt(i));
            }
        }
        QName += "00";
        return QName;
    }

    public static String numToHex(int num){
        String hex = Integer.toHexString(num);
        if(hex.length()>2){
            System.out.println("section in the host name to long");
        }

        if(hex.length()==1){
            hex = "0"+hex;
        }
        return hex;
    }

    public static String getQType(DNSNode n){
        int code = n.getType().getCode();
        return numToHex(code,4);

    }
    public static String numToHex(int num, int numberOfDigit){
        String hex = Integer.toHexString(num);
        if(hex.length()>2){
            System.out.println("section in the host name to long");
        }

        while(hex.length()<numberOfDigit) {
            hex = "0" + hex;
        }
        return hex;
    }


    @Override
    public String toString() {
        return QNAME+QTYPE+QCLASS;
    }
}
