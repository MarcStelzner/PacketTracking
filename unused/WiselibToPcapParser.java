package packettracking.unused;

import packettracking.objects.MACPacket;

import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.util.ArrayList;

public class WiselibToPcapParser {

	ArrayList<MACPacket> packets;
	
	/**
	 * @param args
	 */
	public WiselibToPcapParser(){		 
	}
	
	/**
	 * Main Method of the Parser, initializing each controlsequence
	 */
	public void run(){
		oldTestMethod();
	}
	
	

	
	
	public static void oldTestMethod(){
		FileInputStream input;
		String thisString = "";
		try{
			input = new FileInputStream("C:/Users/Marc/workspace/Packet Tracking/src/minimalPcap2.pcap");
			if(input != null){
				int read;
			    while((read = input.read()) != -1){
			    	String tmpString = Integer.toHexString(read);
			    	if(tmpString.length() < 2){
			    		tmpString = "0" + tmpString;
			    	}
			    	thisString += "-" + tmpString;
			        //System.out.print(Integer.toHexString(read) + " ");
			    }
			}
		} catch(Exception e){
			System.out.print("Error beim Einlesen: " + e);
		}
		System.out.println(thisString);
		
		FileOutputStream output;
		
		//erst der global header (konstruiert)
		byte[] testOutputNative = new byte[] {(byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte)0xff, (byte)0xff, 0x00, 0x00, 0x00, (byte)195, 
				//dann der packet header (konstruiert)
				0x4a, (byte)0xc4, (byte)0xef, 0x16, 00, 0x09, 0x45, (byte)0xb3, 0x00, 0x00, 0x00, (byte)0x24, 0x00 ,0x00, 0x00, (byte)0x24,
				//hier (TODO: noch fiktiv) MAC header
				0x01, (byte)0x88, 0x00, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, 0x02, 0x00, 0x02, 0x00,
				//hier nun MAC Payload: 6lowpan-frame, udp-frame und payload
				107,59,0,0,1,58,2,(byte)133,0,(byte)124,46,0,0,0,0,1,1,0,0,0,0,0,0,
				//hier (TODO: noch fiktiv) MAC CRC
				(byte)0xb5, (byte)0xc6};
		
		for (byte b : testOutputNative) {
			System.out.format("0x%x ", b);
		}
		
		System.out.println("\n Länge: " + (testOutputNative.length-40));
				
		try{
			output = new FileOutputStream("C:/Users/Marc/workspace/Packet Tracking/src/testOutputNative.pcap");
			output.write(testOutputNative);
			
		} catch(Exception e){
			System.out.print("Error beim Einlesen: " + e);
		}
	}
	
	void createAPcap(){

	}

}
