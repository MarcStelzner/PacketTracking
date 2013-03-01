package packettracking.controller;

import java.util.ArrayList;

import packettracking.model.MACPacket;
import packettracking.view.EncoderView;

/**
 * The Encoder-class prints the packet-objects to .pcap file as an export
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-15        
 */
public class Encoder {
	
	EncoderView view;
	
	public Encoder(){
		view = new EncoderView();
	}
	
	/**
	 * Main function of the class calls view to ask user for packet export
	 *
	 * @param packets the packet logs to print
	 */
	public void printPcapFile(ArrayList<MACPacket> packets){
		//Ask user if he wants to export the data to .pcap
		if(view.askForExport()){
			startExport(packets);
		}
	}
	
	/**
	 * This class writes the collected packets to a file.
	 * 1. Pcap-File-Header
	 * 2. Pcap-Packet-Header
	 * 3. Packet 		(and back to step 2 for all packets)
	 * 
	 * @param packets the packet logs to print
	 */
	private void startExport(ArrayList<MACPacket> packets){
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
		
		//write all packets to an array
		for(int i = 0; i<packets.size();i++){
			byte[] tmpPcapArray = new byte[pcapArray.length+packets.get(i).toBytes().length];
			System.arraycopy(pcapArray, 0, tmpPcapArray, 0, pcapArray.length);
			System.arraycopy(packets.get(i).toBytes(), 0, tmpPcapArray, pcapArray.length, packets.get(i).toBytes().length);
			pcapArray = tmpPcapArray;
		}
		
		//use view to ask for export-location
		view.exportDataToFile(pcapArray);  
	}
}
