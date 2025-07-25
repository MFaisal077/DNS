// IN2011 Computer Networks
// Coursework 2024/2025 Resit
//
// Submission by
// YOUR_NAME_GOES_HERE
// YOUR_STUDENT_ID_NUMBER_GOES_HERE
// YOUR_EMAIL_GOES_HERE

import java.net.InetAddress;

// DO NOT EDIT starts
interface ResolverInterface {
    public void setNameServer(InetAddress ipAddress, int port) throws Exception;

    public InetAddress iterativeResolveAddress(String domainName) throws Exception;
    public String iterativeResolveText(String domainName) throws Exception;
    public String iterativeResolveName(String domainName, int type) throws Exception;
}
// DO NOT EDIT ends


public class Resolver implements ResolverInterface {

    public void setNameServer(InetAddress ipAddress, int port) throws Exception {
	// This method must be called first.
	// You can assume that the IP address and port number lead to
	// a working domain name server which supports iterative
	// queries.
	throw new Exception("Not implemented");
    }

    public InetAddress iterativeResolveAddress(String domainName) throws Exception {
	// You can assume that domainName is a valid domain name.
	//
	// Performs a iterative resolution for domainName's A resource
	// record using the name server given by setNameServer.
	//
	// If the domainName has A records, it returns the IP
	// address from one of them.  If there is no record then it
	// returns null.  In any other case it throws an informative
	// exception.
	throw new Exception("Not implemented");
    }
    
    public String iterativeResolveText(String domainName) throws Exception {
	// You can assume that domainName is a valid domain name.
	//
	// Performs a iterative resolution for domainName's TXT resource
	// record using the name server given by setNameServer.
	//
	// If the domainName has TXT records, it returns the string
	// contained one of the records. If there is no record then it
	// returns null.  In any other case it throws an informative
	// exception.
	throw new Exception("Not implemented");
    }
    
    public String iterativeResolveName(String domainName, int type) throws Exception {
	// You can assume that domainName is a valid domain name.
	//
	// You can assume that type is one of NS, MX or CNAME.
	//
	// Performs a iterative resolution for domainName's resource
	// record using the name server given by setNameServer.
	//
	// If the domainName has appropriate records, it returns the
	// domain name contained in one of the records. If there is no
	// record then it returns null.  In any other case it throws
	// an informative exception.
	throw new Exception("Not implemented");
    }
}
