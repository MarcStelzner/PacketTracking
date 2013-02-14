package packettracking.controller;

import java.util.ArrayList;

import packettracking.model.MACPacket;
import packettracking.view.EncoderView;


public class Encoder {
	
	EncoderView view;
	
	public Encoder(){
		view = new EncoderView();
	}
	
	/**
	 * This class writes the collected packets to a file.
	 * 1. Pcap-File-Header
	 * 2. Pcap-Packet-Header
	 * 3. Packet 		(and back to step 2 for all packets)
	 */
	public void printPcapFile(ArrayList<MACPacket> packets){
		//Ask user if he wants to export the data to .pcap
		if(view.askForExport()){
			startExport(packets);
		}
	}
	
	private void startExport(ArrayList<MACPacket> packets){
		byte[] outputArray = new byte[0];
		byte[] oldOutputArray;
		
		System.out.println("--- Starting to print Pcap-File ---");
		System.out.println("Start writing Pcap Header ...");
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
		
		System.out.println("Pcap header done. \nStart collecting "+packets.size()+" packets ...");
		
		oldOutputArray = pcapArray;
		outputArray = pcapArray;
		
		//write all packets to an array
		for(int i = 0; i<packets.size();i++){
			outputArray = new byte[oldOutputArray.length+packets.get(i).toBytes().length];
			System.arraycopy(oldOutputArray, 0, outputArray, 0, oldOutputArray.length);
			System.arraycopy(packets.get(i).toBytes(), 0, outputArray, oldOutputArray.length, packets.get(i).toBytes().length);
			oldOutputArray = outputArray;
		}
		view.exportDataToFile(outputArray);  
	}
}
