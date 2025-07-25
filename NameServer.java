// IN2011 Computer Networks
// Coursework 2024/2025 Resit
//
// Submission by
// YOUR_NAME_GOES_HERE
// YOUR_STUDENT_ID_NUMBER_GOES_HERE
// YOUR_EMAIL_GOES_HERE

import java.net.InetAddress;

// DO NOT EDIT starts
interface NameServerInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;
    public void handleIncomingQueries(int port) throws Exception;
}
// DO NOT EDIT ends


public class NameServer implements NameServerInterface {

    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
	// This method must be called first.
	// You can assume that the IP address and port number lead to
	// a working domain name server which supports iterative
	// queries.
	throw new Exception("Not implemented");
    }

    public void handleIncomingQueries(int port) throws Exception {
	// You can assume that port is a valid UDP port number.
	//
	// Listens for incoming DNS queries on the given port number
	// and responds to them by using cached values and performing
	// iterative resolution.
	throw new Exception("Not implemented");
    }
}
