// IN2011 Computer Networks
// Coursework 2024/2025 Resit
//
// Submission by
// YOUR_NAME_GOES_HERE
// YOUR_STUDENT_ID_NUMBER_GOES_HERE
// YOUR_EMAIL_GOES_HERE

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.file.attribute.UserDefinedFileAttributeView;
import java.util.Random;

// DO NOT EDIT starts
interface StubResolverInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;

    public InetAddress recursiveResolveAddress(String domainName) throws Exception;
    public String recursiveResolveText(String domainName) throws Exception;
    public String recursiveResolveName(String domainName, int type) throws Exception;
}
// DO NOT EDIT ends


public class StubResolver implements StubResolverInterface {

    private InetAddress dnsServer;
    private int port;

    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
        // This method must be called first.
        // You can assume that the IP address and port number lead to
        // a working domain name server which supports recursive
        // queries.
        if (ipAddress == null || port <= 0 || port > 65535) {
            throw new Exception("Invalid DNS server IP or port");
        }
        this.dnsServer = ipAddress;
        this.port = port;
        //throw new Exception("Not implemented");
    }

    public InetAddress recursiveResolveAddress(String domainName) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // Performs a recursive resolution for domainName's A resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has A records, it returns the IP
        // address from one of them.  If there is no record then it
        // returns null.  In any other case it throws an informative
        // exception.
        //throw new Exception("Not implemented");
        if (dnsServer == null || port == 0) {
            throw new Exception("Name server not set");
        }

        byte[] query = buildQuery(domainName, 1); // A record type = 1
        byte[] response = sendUDPQuery(query);

        return parseARecord(response);

    }
    private byte[] buildQuery(String domainName, int qtype) {
        ByteBuffer buffer = ByteBuffer.allocate(512);

        Random rand = new Random();
        buffer.putShort((short) rand.nextInt(65536)); // Transaction ID
        buffer.putShort((short) 0x0100);              // Flags (recursion desired)
        buffer.putShort((short) 1);                   // QDCOUNT
        buffer.putShort((short) 0);                   // ANCOUNT
        buffer.putShort((short) 0);                   // NSCOUNT
        buffer.putShort((short) 0);                   // ARCOUNT

        String[] labels = domainName.split("\\.");
        for (String label : labels) {
            buffer.put((byte) label.length());
            buffer.put(label.getBytes());
        }
        buffer.put((byte) 0); // end of domain name

        buffer.putShort((short) qtype); // QTYPE
        buffer.putShort((short) 1);     // QCLASS = IN

        byte[] result = new byte[buffer.position()];
        System.arraycopy(buffer.array(), 0, result, 0, result.length);
        return result;
    }

    // Sends UDP packet and returns the response
    private byte[] sendUDPQuery(byte[] request) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(5000); // 5s timeout
        DatagramPacket packet = new DatagramPacket(request, request.length, dnsServer, port);
        socket.send(packet);

        byte[] response = new byte[512];
        DatagramPacket responsePacket = new DatagramPacket(response, response.length);
        socket.receive(responsePacket);
        socket.close();
        return response;
    }

    // Parses the A record response and extracts the IPv4 address
    private InetAddress parseARecord(byte[] response) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(response);

        buffer.getShort(); // Transaction ID
        short flags = buffer.getShort(); // Flags
        int rcode = flags & 0x000F;
        if (rcode == 3) return null; // NXDOMAIN
        if (rcode != 0) throw new Exception("DNS error: RCODE " + rcode);

        int qdcount = buffer.getShort() & 0xFFFF;
        int ancount = buffer.getShort() & 0xFFFF;
        buffer.getShort(); // NSCOUNT
        buffer.getShort(); // ARCOUNT

        // Skip the question section
        for (int i = 0; i < qdcount; i++) {
            skipName(buffer);     // QNAME
            buffer.getShort();    // QTYPE
            buffer.getShort();    // QCLASS
        }

        // Read the answer section
        for (int i = 0; i < ancount; i++) {
            skipName(buffer);         // NAME
            int type = buffer.getShort() & 0xFFFF;
            buffer.getShort();        // CLASS
            buffer.getInt();          // TTL
            int rdlength = buffer.getShort() & 0xFFFF;

            if (type == 1) { // A record
                byte[] addrBytes = new byte[rdlength];
                buffer.get(addrBytes);
                return InetAddress.getByAddress(addrBytes);
            } else {
                buffer.position(buffer.position() + rdlength); // Skip unwanted record
            }
        }

        return null; // No A record found
    }

    private String parseTXTRecord(byte[] response) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(response);

        buffer.position(4);
        int qdcount = buffer.getShort() & 0xFFFF;
        int ancount = buffer.getShort() & 0xFFFF;
        buffer.getShort(); // NSCOUNT
        buffer.getShort(); // ARCOUNT

        // Skip over the question section
        for (int i = 0; i < qdcount; i++) {
            skipName(buffer);
            buffer.getShort(); // QTYPE
            buffer.getShort(); // QCLASS
        }

        // Parse the answer section
        for (int i = 0; i < ancount; i++) {
            skipName(buffer);
            int type = buffer.getShort() & 0xFFFF;
            buffer.getShort(); // CLASS
            buffer.getInt(); // TTL
            int rdlength = buffer.getShort() & 0xFFFF;
            if (type == 16) { // TXT
                int txtLen = buffer.get() & 0xFF; // Length of TXT string
                byte[] txtData = new byte[txtLen];
                buffer.get(txtData);
                return new String(txtData);
            } else {
                buffer.position(buffer.position() + rdlength); // Skip non-TXT
            }
        }

        return null;
    }


    private void skipName(ByteBuffer buffer) {
        while (true) {
            byte len = buffer.get();
            if ((len & 0xC0) == 0xC0) {
                buffer.get(); // pointer: skip next byte
                break;
            } else if (len == 0) {
                break;
            } else {
                buffer.position(buffer.position() + len);
            }
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) hex.append(String.format("%02X ", b));
        return hex.toString();
    }


    public String recursiveResolveText(String domainName) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // Performs a recursive resolution for domainName's TXT resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has TXT records, it returns the string
        // contained one of the records. If there is no record then it
        // returns null.  In any other case it throws an informative
        // exception.

        if (dnsServer == null || port == 0) {
            throw new Exception("Name server not set");
        }
        byte[] response = sendQuery(domainName, 16); // 16 = TXT record
        return parseTXTRecord(response);
        //throw new Exception("Not implemented");
    }
    private byte[] sendQuery(String domainName, int qtype) throws Exception {
        if (dnsServer == null || port == 0) {
            throw new Exception("Name server not set");
        }

        if (!domainName.matches("[a-zA-Z0-9.-]+")) {
            throw new Exception("Invalid domain name");
        }

        DatagramSocket socket = new DatagramSocket();
        try {
            socket.setSoTimeout(5000); // 5 seconds timeout
            byte[] request = buildQuery(domainName, qtype);
            DatagramPacket packet = new DatagramPacket(request, request.length, dnsServer, port);
            socket.send(packet);

            byte[] response = new byte[512];
            DatagramPacket responsePacket = new DatagramPacket(response, response.length);
            socket.receive(responsePacket);
            return response;
        } catch (SocketTimeoutException e) {
            throw new Exception("DNS server timeout");
        } catch (Exception e) {
            throw new Exception("DNS query failed: " + e.getMessage());
        } finally {
            socket.close();
        }
    }

    public String recursiveResolveName(String domainName, int type) throws Exception {
        // You can assume that domainName is a valid domain name.
        //
        // You can assume that type is one of NS, MX or CNAME.
        //
        // Performs a recursive resolution for domainName's resource
        // record using the name server given by setNameServer.
        //
        // If the domainName has appropriate records, it returns the
        // domain name contained in one of the records. If there is no
        // record then it returns null.  In any other case it throws
        // an informative exception.
        //throw new Exception("Not implemented");
        if (dnsServer == null || port == 0) {
            throw new Exception("Name server not set");
        }

        if (type != 2 && type != 5 && type != 15) {
            throw new Exception("Unsupported type: " + type);
        }

        byte[] response = sendQuery(domainName, type);
        return parseNameRecord(response, type);
    }
    private String parseNameRecord(byte[] response, int type) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(response);

        buffer.position(4);
        int qdcount = buffer.getShort() & 0xFFFF;
        int ancount = buffer.getShort() & 0xFFFF;
        buffer.getShort(); // NSCOUNT
        buffer.getShort(); // ARCOUNT

        for (int i = 0; i < qdcount; i++) {
            skipName(buffer);
            buffer.getShort(); // QTYPE
            buffer.getShort(); // QCLASS
        }

        for (int i = 0; i < ancount; i++) {
            skipName(buffer);
            int recordType = buffer.getShort() & 0xFFFF;
            buffer.getShort(); // CLASS
            buffer.getInt();   // TTL
            int rdlength = buffer.getShort() & 0xFFFF;

            if (recordType == type) {
                if (type == 15) buffer.getShort(); // skip MX preference
                return readName(buffer);
            } else {
                buffer.position(buffer.position() + rdlength); // skip non-matching
            }
        }

        return null;
    }
    private String readName(ByteBuffer buffer) {
        StringBuilder name = new StringBuilder();
        while (true) {
            byte len = buffer.get();
            if ((len & 0xC0) == 0xC0) {
                int pointer = ((len & 0x3F) << 8) | (buffer.get() & 0xFF);
                int oldPos = buffer.position();
                buffer.position(pointer);
                name.append(readName(buffer));
                buffer.position(oldPos);
                break;
            } else if (len == 0) {
                break;
            } else {
                byte[] label = new byte[len];
                buffer.get(label);
                name.append(new String(label)).append('.');
            }
        }
        return name.toString();
    }

}
