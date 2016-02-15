//Stop-and-Wait Transmitter class

package transmitter; //Please include the RC4 class in the same package
import java.util.*;
import java.net.*;
import java.nio.*;

public class StopAndWaitTransmitter 
{		
	private static final int PORT = 9999; //Port to send data
	private static final int MAX_NO_OF_PACKETS = 17; //Maximum No. of packets = 17 (16 packets containing 30 payload bytes and last packet containing 20 payload bytes
	private static int seqNo = 1483645224; //Initial sequence no. Should be the same as receiver
	private static final byte[] KEY = {54, 0, -21, -26, -64, -45, -118, 17, 126, -72, 115, 105, 52, 18, 52, -50}; //Key for RC4. Should be the same as the one generated in the receiver
	private static byte[] data = new byte[500]; //Array for storing 500 bytes of payload
	private static byte[] dataPacket = new byte[40]; //Array for creating a packet to be sent
	private static byte[] packetType = {85, -86}; //Packet type can be either 0x55 or 0xaa
	private static byte[] integrityValue = new byte[4]; //For storing locally calculated Integrity check value of 4 bytes
	private static byte[] sequenceNo; //Byte array for sending sequence no. as 4 bytes
	private static byte[] length = {30, 20}; //Length of payload is either 30 or 20 bytes
	 
	public static void main(String[] args) throws Exception
	{			
		int payloadIndex = 0; //Payload index for sending 30 or 20 bytes of payload at a time
		int timeout = 1000; //Initial timeout value is 1 second 
		byte[] ACK = new byte[9]; //Byte array for storing received ACK 
		new Random().nextBytes(data); //Generating 500 bytes of random data
		
	    InetAddress IPAddress = InetAddress.getLocalHost(); //Form IP Address. In this case, local host
	    
	    DatagramPacket rPacket = new DatagramPacket(ACK,ACK.length); //Datagram packet for storing received ACK
	    
	    DatagramSocket s = new DatagramSocket(); //Creating a Datagram socket for sending the packets
	    
	    int i = 1; //Initialize loop variable for counting the no. of sent packets
	    
	    while(i <= MAX_NO_OF_PACKETS)
	    {	
	    	RC4 rc4 = new RC4(KEY); //Creating an RC4 object and initializing with the key
	    	 
	    	if (i < 17) //For first 16 packets
	    	{	
	    		dataPacket = formPacket(0,0,payloadIndex,30); //Call formPacket method and assign it to dataPacket
	    		
	    		for(int k = 0; k < 4; k++)
	    			dataPacket[k+36]=0; /*Setting last 4 bytes of dataPacket to zero. 
	    								This is needed because in future iterations, it will contain previous integrity check values.*/
	    		
		    	integrityValue = integrityCompress(rc4.encrypt(dataPacket), 1); /*Encrypt the data packet and pass this to integrity compress method.
		    																	Then assign it to the integrityValue array*/
		    	
		    	System.arraycopy(integrityValue,0,dataPacket,36,4); //Append the integrity value to last 4 bytes
		    	
	    	}
	    	
	    	else if (i == 17) //For the last packet, follow the same procedure except for the changes noted below
	    	{
		    	dataPacket = formPacket(1,1,payloadIndex,20); //Packet type is 0xaa, Payload length is 20
		    	
		    	for(int k=0; k<14; k++)
	    			dataPacket[k+26]=0;
		    	
	    		integrityValue = integrityCompress(rc4.encrypt(dataPacket),2);
	    		System.arraycopy(integrityValue,0,dataPacket,26,4);
	
	    	}

	    	DatagramPacket packet = new DatagramPacket(dataPacket, dataPacket.length, IPAddress, PORT); //Creating a datagram packet for sending the data packet
	    	
			s.send(packet); //Sending the packet    	
		    s.setSoTimeout(timeout); //Set initial timeout value of 1 second
		    
	    	timeoutMethod(packet,rPacket,s,timeout); //Call timeotMethod to receive and initiate timer.
	    	
	    	s.setSoTimeout(timeout); //Reset timeout, packet received
	    	
	    	ACK = rPacket.getData(); //ACK Stores the received ACK packet
	    	
	    	byte[] ackNo = new byte[4]; //Store received Ack no.
	    	
	    	for(int j = 0; j < 4; j++) //Copy received Ack No. from ACK
	    		ackNo[j] = ACK[j+1];
	    	
	    	int x = ByteBuffer.wrap(ackNo).getInt(); //Convert ACK No. to int
	    	
	    	boolean a = ackCheck(ACK); //Calls ackCheck method and assigns the boolean value to variable a
	    
	    	/*An acknowledgment packet can only be accepted if:

			a) The locally calculated integrity check value for the acknowledgment packet is equal to
			the value of the integrity check field in the acknowledgment packet.
			b) It is an acknowledgment packet (packet type: ffh) with the correct acknowledgment
			number.*/
	    	
	    	if ((a == false) ||  (ACK[0]!= -1) || (x!=(seqNo+30)))  //ACK packet is corrupted, resend the same packet
	    		continue;
	    		    		
	    	payloadIndex += 30; //Increment payload index by 30
	    	i++; //Increment i
	    	seqNo += 30; //Increment Sequence No. by 30, as protocol counts bytes
	    	
	    }
	    
		System.out.println("All data bytes sent successfully! \nSent Payload sequence: \n"+Arrays.toString(data)); 
	    
	} //main()
	
	//Method creates data packet except for the integrity check field
	public static byte[] formPacket(int pType, int len, int payloadIndex, int payloadLen )
	{	
		sequenceNo = ByteBuffer.allocate(4).putInt(seqNo).array(); //Convert sequence no. into 4 bytes
		
		System.arraycopy(packetType,pType,dataPacket,0,1); //Copy packet type
		
		System.arraycopy(sequenceNo,0,dataPacket,1,4); //Copy sequence no.
		
		System.arraycopy(length,len,dataPacket,5,1); //Copy length of payload
		
		System.arraycopy(data,payloadIndex,dataPacket,6,payloadLen); //Copy payload
		
		return dataPacket; //Return the data packet
		
	} //formPacket()
	
	//Method implements the timeout feature using nested try-catch blocks
	public static void timeoutMethod(DatagramPacket packet,DatagramPacket rPacket, DatagramSocket s, int timeout) throws Exception
	{
		try
    	{			
    	s.receive(rPacket); //Try to receive packet
        }
    	
    	catch (SocketTimeoutException e) //Packet not received
    	{ 
    	timeout*=2; //Double timeout
    	s.setSoTimeout(timeout); //Set new timeout value
    	System.out.println("1st timeout: Waiting for the receiver's response "+e);
    	s.send(packet); //Resend packet
    	
    		try{
    			s.receive(rPacket);
    		   }
    		
    		catch (SocketTimeoutException f) 
    			{
    			timeout*=2;
    			s.setSoTimeout(timeout);
    			System.out.println("2nd timeout: Waiting for the receiver's response "+f);
    			s.send(packet);
    			
    				try{
    					s.receive(rPacket);
    					}
    				
    				catch (SocketTimeoutException g)
				    	{
    					timeout*=2;
				    	s.setSoTimeout(timeout);
				    	System.out.println("3rd timeout: Still waiting for the receiver's response "+g);
				    	s.send(packet);
				    	
				    	try{
					    	s.receive(rPacket);
					    	}
				    	
				    	catch (SocketTimeoutException h)
				    		{
				    		System.out.println("4th timeout: Communication failure! \nExiting...");
				    		System.exit(0);
				    		}
				    	}
    			}
    	}
		
	} //timeoutMethod()
	
	public static byte[] integrityCompress(byte[] b, int type)
	{	
		byte[] c = new byte[4];
		
		if(type==1) //Type 1 : First 16 packets - Compresses Cipher text to 4 bytes by XOring 4 bytes
		{ 	
			for(int j=0; j<c.length; j++)
			{ 	
			 c[j] = (byte) (b[j]^b[j+4]^b[j+8]^b[j+12]^b[j+16]^b[j+20]^b[j+24]^b[j+28]^b[j+32]);
			
			}
		}
		
		else if(type==2) //Type 2 : Last packet  - (Implicit zero padding occurs)
		{
			
			for(int j=0; j<c.length; j++)
			{ 	
			 c[j] = (byte) (b[j]^b[j+4]^b[j+8]^b[j+12]^b[j+16]^b[j+20]^b[j+24]);
				
			}
		}
		
		else if(type==3) //Type 3 - Calculate integrity field for ACK packet
		{
			
			for(int j = 0; j < 4; j++)
			{ 	
			 c[j] = (byte) (b[j]^b[j+4]);
				
			}
		}
		
		return c; //Return the compressed bytes
		
	} //integrityCompress()
	
	//Method returns true only if locally calculated integrity check equals the received integrity value
	public static boolean ackCheck(byte[] ACK)
	{	
		RC4 rc4ACK = new RC4(KEY);
		
		byte[] ackIntegrityRx = new byte[8]; //ackIntegrityRx - to store the received integrity check value
		
    	for(int j = 0; j < 4; j++)
    		ackIntegrityRx[j] = ACK[j+5];
    	
    	byte[] ackTemp = new byte[8]; //ackTemp will be used to calculate the integrity for the ACK packet Locally
    	
    	for(int j = 0; j < 5; j++)
    		ackTemp[j] = ACK[j];
    	
    	byte[] ackIntegrity = new byte[8]; //ackIntegrity - will store locally calculated integrity value
    	
    	ackIntegrity = integrityCompress(rc4ACK.encrypt(ackTemp),3); //Call RC4 encrypt function and pass this value to integrityCompress to compress the bytes
    	
    	byte[] ackIntegrityPadded = new byte[8]; //Zero padding with 4 zeroes, so that received and calculated integrity values are identical
    	
    	System.arraycopy(ackIntegrity, 0, ackIntegrityPadded, 0, 4);
    	    	   	
    	return Arrays.equals(ackIntegrityPadded, ackIntegrityRx); //Returning the compared boolean value
    	
	}//ackCheck
	
} //class
