//Stop-and-Wait Receiver

package receiver; //Please include the RC4 class in the same package
import java.util.*;
import java.net.*;
import java.nio.*;

public class StopAndWaitReceiver 
{	
	//Declaring and initializing private fields of the class
	
	private static final int PORT = 9999; //Receiver listens to port 9990
	private static final int MAX_PAYLOAD_SIZE = 30; //Defining Maximum Payload size
	private static final byte[] KEY = {54, 0, -21, -26, -64, -45, -118, 17, 126, -72, 115, 105, 52, 18, 52, -50}; //Key for RC4
	private static byte[] data = new byte[500];   //Byte array for storing the received payload sequence
	private static int seqNo = 1483645224; //Initial sequence No.
	private static int ACKNo = seqNo + 30; //Define initial ACK No.
	private static int offset=0; //Offset in data array, needed to store payload as a sequence
	private static int count=0; //Used to count the no. of packets received

	public static void main(String[] args) throws Exception
	{
		// TODO Auto-generated method stub
		
		//private static final byte[] key = new byte[16]; 
       	//new Random().nextBytes(key); <<< Used to generate a random byte sequence for key (For the first time)
    	//private static int seqNo; new Random().nextInt(seqNo); <<< Used to generate a random int for sequence no. (For the first time)
    	
    	DatagramSocket s = new DatagramSocket(PORT); //Create a datagram socket to listen to the PORT No.
    		
    	//Start receiving the data packets
    	
    	while (true) //Receiver listens 'forever'
    	{	
    		//Creating a new RC4 object and initializing with key for every iteration of the loop
    		//This is required to avoid mismatch between received and calculated integrity check values
    		
    		RC4 rc4 = new RC4(KEY);  
    		byte[] ACK = new byte[9]; //Byte array for send ACK  		
    		byte[] calculatedIntegrity = new byte[4]; //Byte array for storing locally calculated integrity check value
    		byte[] temp = new byte[40]; //Byte array for storing all received bytes except integrity check field
    		byte[] rPayload = new byte[MAX_PAYLOAD_SIZE]; //Byte array for storing the payload of each packet
    		byte[] receivedIntegrity = new byte[4]; //Byte array for storing Received integrity check bytes
    		byte[] rData = new byte[40]; //Byte array for storing all the received bytes
    		
        	DatagramPacket rDataPacket = new DatagramPacket(rData, rData.length); //Create a Datagram packet for receiving the packet
    		    		
    		s.receive(rDataPacket); //Receive packet
    		rData = rDataPacket.getData(); //Store all received bytes in rData
    		count++; //Increment count
    	 	int pType = rData[0]; //Getting packet type
    	 	
    		byte[] rSequenceNo = new byte[4]; //Define a new byte array for storing sequence no. as 4 bytes

    		for (int i = 0; i < 4; i++)
    			rSequenceNo[i] = rData[i+1]; //Getting Sequence No. as a byte array

    		int x = ByteBuffer.wrap(rSequenceNo).getInt(); //Convert sequence No. into 'int' using Byte Buffer
    	
    		// Calculating integrity value for the packet locally and comparing with received integrity
    		
    		if (pType == 85) //If additional packets are to be sent, i.e. packet type is 0x55
    			{						
    				for (int i = 0; i < 36; i++)
    					temp[i] = rData[i]; //temp contains all bytes from received data except integrity check  				
   
    				calculatedIntegrity = integrityCompress(rc4.encrypt(temp),1); //Calculate the integrity value of the packet locally
    				
	    			/*System.out.printf("\nCalculated Integrity for P%d: ",count);
	    			System.out.println(Arrays.toString(calculatedIntegrity));*/
	    					
    				for (int i = 0; i < 4 ; i++)
    					receivedIntegrity[i] = rData[i + 36]; //Storing received integrity check bytes 
    				
	    			/*System.out.printf("\nReceived Integrity for P%d: ",count);
	    			System.out.println(Arrays.toString(receivedIntegrity));	*/
    				
    				for(int i = 0; i < 30; i++)
    					rPayload[i] = rData[i+6]; //Storing payload in rPayload array
    			}
    		
    		else if (pType == -86) //If this is the last packet, i.e. packet type 0xaa
    			{
    			
	    			for (int i = 0; i < 26; i++)
						temp[i] = rData[i]; //temp contains all bytes except integrity check
	    			
	    		
					calculatedIntegrity = integrityCompress(rc4.encrypt(temp),2);
					
					for (int i = 0; i < 4 ; i++)
						receivedIntegrity[i] = rData[i + 26];	
					
					for(int i = 0; i < 20; i++)
						rPayload[i] = rData[i+6]; //Storing payload in rPayload array							    			
				
    			}
    		
    		/*Before sending ACK, check for the following conditions:
    		  	a) The locally calculated integrity check value for the data packet is equal to the value of the
				integrity check field in the data packet.
				b) It is a data packet (packet type: 55h or aah) with the correct (in-order) sequence number.
				c) The length of the payload is less than or equal to MPS.
    		 */
    		
    		if(( Arrays.equals(receivedIntegrity, calculatedIntegrity)) && ((pType == 85) || (pType == -86)) && (x == ACKNo-30) && (rPayload.length <= MAX_PAYLOAD_SIZE))
    		{
    			//Send ACK Packet, if all conditions are satisfied
    			
    			ACK = formACKPacket(ACK); //Calling formACKPacket method
    			
    			DatagramPacket ACKPacket = new DatagramPacket(ACK, ACK.length, rDataPacket.getAddress(), rDataPacket.getPort()); //Creating datagram packet for sending ACK
    			s.send(ACKPacket); //Send ACK
    			
    			ACKNo += 30; //Increment ACK No. by 30 as protocol counts bytes
    			
    			//Store payload sequence in data array
    			if(pType == 85)
    			{
    				for (int i = 0; i < MAX_PAYLOAD_SIZE; i++)
    					data[i+offset] = rPayload[i];
    				
    					offset += 30; //Increment payload offset by 30   					
    			}
    			
    			else if (pType == -86) //If last data packet (Packet type: 0xaa)
    			{
    				for (int i = 0; i < MAX_PAYLOAD_SIZE-10; i++)
        				data[i+offset] = rPayload[i];
    				
    				//Printing received payload sequence because 0xaa means this is the last data packet 
    				System.out.println("Received payload sequence: ");
    				
    				System.out.println(Arrays.toString(data)+"\n");
    				
    				//After last packet is received, reset Seq No., ACK No. and offset to the initial values
	    			seqNo = 1483645224;
	      			ACKNo = seqNo + 30;
	      			offset=0;
    				
    			}

    		}
    		
    		else
    			System.out.printf("Packet %d dropped! Corrupted or incorrect sequence number. %n", count);
    			    		
    	} //while
    	
	} //main()
	   	
    	public static byte[] integrityCompress(byte[] b, int type) //Method compresses integrity value to 4 bytes
    	{	
    		byte[] c = new byte[4]; 
    		
    		if(type == 1) //First 16 packets (Type 1) - Compresses Cipher text to 4 bytes by XOring 
    		{ 	
    			for(int j = 0; j < c.length; j++)
    		{ 	
    			 c[j] = (byte) (b[j]^b[j+4]^b[j+8]^b[j+12]^b[j+16]^b[j+20]^b[j+24]^b[j+28]^b[j+32]);
    			
    		}
    		}
    		
    		else if(type == 2) //Last packet (Type 2) - (Implicit zero padding occurs)
    		{

    			for(int j = 0; j < c.length; j++)
    			{ 	
    				 c[j] = (byte) (b[j]^b[j+4]^b[j+8]^b[j+12]^b[j+16]^b[j+20]^b[j+24]); //Compresses Cipher text to 4 bytes by XOring 
    				
    			}
    		}
    		
    		else if(type == 3) //Type 3 - Calculate integrity field for ACK packet
    		{
    			
    			for(int j = 0; j < c.length; j++)
    			{ 	
    				 c[j] = (byte) (b[j]^b[j+4]); //Compresses Cipher text to 4 bytes by XOring 
    				
    			}
    		}
    		
    		return c; //Return the compressed integrity check value
    		
    	} //integrityCompress()
    			
    	public static byte[] formACKPacket(byte[] ACK) //Method forms ACK Packets 
    	{	
    		RC4 rc4ACK = new RC4(KEY); 	//Create a new object and initialize with the key
    		
    		byte[] ACKPacketType = {-1}; 	//ACK Packet type is always 0xff
    		
    		byte[] ACKNumber = new byte[4]; 	//For storing ACK No. as 4 bytes
    		
    		byte[] ACKIntegrity = new byte[4]; 	//For storing ACK Integrity value
    		
    		byte[] ACKTemp = new byte[8]; 	//For storing all values in ACK packet except for integrity field
    		
    		System.arraycopy(ACKPacketType,0,ACK,0,1); 	//Copy ACK packet type
    		
    		ACKNumber = ByteBuffer.allocate(4).putInt(ACKNo).array(); 	//Convert ACK No. into 4 bytes
    		
    		System.arraycopy(ACKNumber,0,ACK,1,4); 	//Copy ACK No.
    		
    		System.arraycopy(ACK,0,ACKTemp,0,5); 	//Copy the formed bytes into ACKTemp
    		
    		ACKIntegrity = integrityCompress(rc4ACK.encrypt(ACKTemp),3); 	//Encrypt ACKTemp and pass the value to integrityCompress method
    		
    		System.arraycopy(ACKIntegrity,0,ACK,5,4); 	//Finally copy over the compressed integrity value to the last 4 bytes of ACK
    		
    		return ACK; 	//return the formed ACK packet
    		
    	} //formACKPacket
    	
} //class


