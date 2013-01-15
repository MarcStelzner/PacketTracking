package packettracking.main;
import java.awt.FileDialog;
import java.awt.Frame;
import java.io.FileOutputStream;
import java.util.ArrayList;

import packettracking.objects.MACPacket;


public class WriteParser {
	
	public WriteParser(){
		
	}
	
	/**
	 * This class writes the collected packets to a file.
	 * 1. Pcap-File-Header
	 * 2. Pcap-Packet-Header
	 * 3. Packet 		(and back to step 2 for all packets)
	 */
	public void printPcapFile(ArrayList<MACPacket> packets){
		byte[] outputArray = new byte[0];
		byte[] oldOutputArray;
		
		System.out.println("--- Going to print Pcap-File ---");
		System.out.println("Start writing Pcap Header...");
		//Create a PCAP Header:
		// 1. Magic Number 		a1b2c3d4	(right order of bytes)
		// 2. Major Version 	0002		(actual version number)
		// 3. Minor Version		0004
		// 4. Timezone(GMT)		00000000 	(zero in practical use)
		// 5. Max. Packetlength	0000ffff 	(~65535 Byte Payload Maximum)
		// 6. data link Type	000000e6	(= 230, means 802.15.4 protocol standard without FCS(CRC))
		byte[] pcapArray = new byte[] {(byte)0xa1, (byte)0xb2, (byte)0xc3, (byte)0xd4, 
				(byte)0x00, (byte)0x02, 
				(byte)0x00, (byte)0x04, 
				(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
				(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, 
				(byte)0x00, (byte)0x00, (byte)0xff, (byte)0xff, 
				(byte)0x00, (byte)0x00, (byte)0x00, (byte)0xe6};
		
		System.out.println("Pcap header done. \nStart collecting "+packets.size()+" packets...");
		
		oldOutputArray = pcapArray;
		outputArray = pcapArray;
		
		//write all packets to an array
		for(int i = 0; i<packets.size();i++){
			System.out.println("Collect packet #"+i+"...");
			outputArray = new byte[oldOutputArray.length+packets.get(i).toBytes().length];
			System.arraycopy(oldOutputArray, 0, outputArray, 0, oldOutputArray.length);
			System.arraycopy(packets.get(i).toBytes(), 0, outputArray, oldOutputArray.length, packets.get(i).toBytes().length);
			oldOutputArray = outputArray;
			System.out.println("Packet #"+i+" done.");
		}
		
		//Open Dialog to save file
		FileDialog fd = new FileDialog(new Frame(), "Choose file to save converted Datalog.", FileDialog.SAVE);
		fd.setFile("output.pcap");
	    fd.setDirectory(".\\");
	    fd.setLocation(50, 50);
	    fd.setVisible(true);
	    
	    //Check for existence of the given address
	    if(!(fd.getFile() == null)){
	    	String address = fd.getDirectory() + fd.getFile();//System.getProperty("file.separator") + fd.getFile();
		    System.out.println(address);
	    	//check ending of file (to be .pcap), otherwise fix it
		    if(!address.endsWith(".pcap")){
		    	address += ".pcap";
		    }
		    
			System.out.println("All packets are done, writing to file "+ address + " ...");

			//try to save at given address
			try{
				FileOutputStream output = new FileOutputStream(address);
				output.write(outputArray);
				fd.dispose();
				System.out.println("Data saved in "+ address);
				System.out.println("Work done, terminating ...");
			} catch(Exception e){
				System.out.print("Error on saving: " + e);
			}
	    } 
	    // Address given is impossible to save at ? --> terminate 
	    else {
	    	System.out.print("Invalid storing-address, terminating ...");
	    }
	}
}
