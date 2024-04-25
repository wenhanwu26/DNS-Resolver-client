package dns;

import DNSMessage.DNSMessage;
import DNSMessage.Header;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    //
    private static int queryLength = 0; //length in bytes

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A dns.DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {


        // TODO (PART 1): Implement this
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(5000);
        byte[] query = DNSMessage.getQueryMessage(node);
//        for(int i = 0;i<query.length;i++){
//            message[i] = query[i];
//        }
        // send request
//        System.out.println(DNSMessage.bytesToHex(query));
        queryLength = query.length;
        DatagramPacket packet = new DatagramPacket(query, query.length, server, 53);
        socket.send(packet);

        short queryid = (ByteBuffer.wrap(Arrays.copyOfRange(query,0,2))).getShort();

        int unsigned = queryid& 0xffff;
        printQuery(unsigned+"",node,server);

        // get response
        byte[] receiveBuf = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveBuf, receiveBuf.length);

        //time out exception
        try {
            socket.receive(receivePacket);
        } catch (SocketTimeoutException e) {
            socket.send(packet);
            printQuery(unsigned+"",node,server);
            try {
                socket.receive(receivePacket);
            } catch (SocketTimeoutException e1) {
                return null;
            }
        }

        // display response
        byte[] response = receivePacket.getData();
        //String received = new String(packet.getData(), 0, packet.getLength());
 //       System.out.println(DNSMessage.bytesToHex(response));

        socket.close();
        ByteBuffer respond = ByteBuffer.wrap(response);

        short responseid = (ByteBuffer.wrap(Arrays.copyOfRange(response,0,2))).getShort();

        //test if transaction ID match
//        System.out.println(responseid ); // unsigned query id
//        System.out.println(queryid);
        if(responseid!=queryid){
            return DNSQueryHandler.buildAndSendQuery(message,server,node);
        }


        //System.out.println(id);
        return new DNSServerResponse(respond,responseid);
    }


    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @param isAA
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache, boolean[] isAA) {
        // TODO (PART 1): Implement this

        Set<ResourceRecord> resourceRecordsSet = new HashSet<ResourceRecord>();
        ArrayList<ResourceRecord> resourceRecordsList = new ArrayList<ResourceRecord>();

        int queryLengthHex = queryLength*2;
        byte[] bytes = new byte[responseBuffer.remaining()];
        responseBuffer.get(bytes, 0, bytes.length);

        Header h = Header.getResponseHeader(Arrays.copyOfRange(bytes,0,queryLengthHex));
        int ANCOUNT = DNSMessage.hexStringtoSingedInt(h.getANCOUNT());
        int NSCOUNT = DNSMessage.hexStringtoSingedInt(h.getNSCOUNT());
        int ARCOUNT = DNSMessage.hexStringtoSingedInt(h.getARCOUNT());
//        System.out.println(DNSMessage.hexStringtoSingedInt(h.getQDCOUNT()));
//        System.out.println(DNSMessage.hexStringtoSingedInt(h.getANCOUNT()));
//        System.out.println(DNSMessage.hexStringtoSingedInt(h.getNSCOUNT()));
//        System.out.println(DNSMessage.hexStringtoSingedInt(h.getARCOUNT()));
//        System.out.println(h.isAA());
//        System.out.println(h.isRCODE());
        isAA[0] = h.isAA();

        if(h.isRCODE()){
            return null; //something went wrong
        }


        String hexName = DNSMessage.bytesToHex(bytes);

        int[] endIndex = new int[1];

        endIndex[0] = queryLengthHex;
        //need to live in the loop to iterate numer of ANCOUNT ..... times

        for(int i = 0;i<ANCOUNT+NSCOUNT+ARCOUNT;i++){

        String hostName = DNSMessage.decodeADomainName(hexName,endIndex[0],endIndex);
 //       System.out.println("Host Name: "+hostName);
//        System.out.println("endIndex: "+endIndex[0]);
        RecordType recordType = DNSMessage.decodeRecordType(hexName,endIndex[0],endIndex);
 //       System.out.println("Record Type: "+recordType);
//        System.out.println("endIndex: "+endIndex[0]);

        endIndex[0]+=4;//skip class field

        long TTL = Long.parseLong(hexName.substring(endIndex[0],endIndex[0]+8),16);
 //       System.out.println("TTL: "+TTL);
        endIndex[0]+=8;

        int RDLENGTH = Integer.parseUnsignedInt(hexName.substring(endIndex[0],endIndex[0]+4),16);
 //       System.out.println("RDLENGTH: " + RDLENGTH); //in byte
        endIndex[0]+=4;
//        System.out.println("endIndex: "+endIndex[0]);

        String RDATA = "";
        if(recordType==RecordType.A) {
            RDATA = DNSMessage.decodeAType(hexName, endIndex[0], endIndex);
  //          System.out.println("RDATA: " + RDATA);
        }else if(recordType==RecordType.NS || recordType==RecordType.CNAME){
            RDATA = DNSMessage.decodeNSType(hexName,endIndex[0],RDLENGTH,endIndex);
   //         System.out.println("RDATA: "+ RDATA);
        }else if(recordType== RecordType.AAAA){
            RDATA = DNSMessage.decodeAAAAType(hexName,endIndex[0],endIndex);
   //         System.out.println("RDATA: "+ RDATA);
        }else{
            RDATA = "----";
   //         System.out.println("RDATA: "+ RDATA);
        }
            ResourceRecord record = new ResourceRecord(hostName,recordType,TTL,RDATA);
            resourceRecordsSet.add(record);
            resourceRecordsList.add(record);
        }
        printResponseAndCache(transactionID& 0xffff,h.isAA(),ANCOUNT,NSCOUNT,ARCOUNT,resourceRecordsList,cache);
        return resourceRecordsSet;
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    public static void printQuery(String id,DNSNode node,InetAddress server) {
        if (verboseTracing) {
            System.out.println();
            System.out.println();
            System.out.println("Query ID     " + id + " " + node.getHostName() + "  " + node.getType().name() + " --> " + server.getHostAddress());
        }
    }

    //print the response, and if the rr is in additional and answer section, cache it
    public static void printResponseAndCache(int ID, boolean isAA, int ANCOUNT, int NSCOUNT, int ARCOUNT, ArrayList<ResourceRecord> records, DNSCache cache){
        boolean caching = true;
        if(verboseTracing) {
            System.out.println("Response ID: " + ID + " Authoritative = " + isAA);
//            for (int i = 0; i < ANCOUNT + NSCOUNT + ARCOUNT; i++) {
//                //System.out.println(i);
//                if (i == 0) {
//                    System.out.println("  Answers (" + ANCOUNT + ")");
//                }
//
//                if (i == ANCOUNT) {
//                    caching = false;
//                    System.out.println("  Nameservers (" + NSCOUNT + ")");
//                }
//
//                if (i == NSCOUNT+ANCOUNT) {
//
//                    caching = true;
//                    System.out.println("  Additional Information (" + ARCOUNT + ")");
//                }
//                if(caching){
//                    cache.addResult(records.get(i));
//                }
//                verbosePrintResourceRecord(records.get(i), records.get(i).getType().getCode());
//
//            }
            System.out.println("  Answers (" + ANCOUNT + ")");
            for(int i = 0;i<ANCOUNT;i++){
                cache.addResult(records.get(i));
                verbosePrintResourceRecord(records.get(i), records.get(i).getType().getCode());
            }
            System.out.println("  Nameservers (" + NSCOUNT + ")");
            for(int i = 0;i<NSCOUNT;i++){
                cache.addResult(records.get(i+ANCOUNT));
                verbosePrintResourceRecord(records.get(i+ANCOUNT), records.get(i+ANCOUNT).getType().getCode());
            }
            System.out.println("  Additional Information (" + ARCOUNT + ")");
            for(int i = 0;i<ARCOUNT;i++){
                cache.addResult(records.get(i+ANCOUNT+NSCOUNT));
                verbosePrintResourceRecord(records.get(i+NSCOUNT+ANCOUNT), records.get(i+NSCOUNT+ANCOUNT).getType().getCode());
            }

        }else{
            for (int i = 0; i < ANCOUNT + NSCOUNT + ARCOUNT; i++) {
                if (i == ANCOUNT) {
                    caching = false;
                }
                if (i == NSCOUNT+ANCOUNT) {
                    caching = true;
                }
                if(caching){
                    cache.addResult(records.get(i));
                }
            }
        }

    }
}

