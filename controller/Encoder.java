package packettracking.controller;
import java.awt.FileDialog;
import java.awt.Frame;
import java.io.FileOutputStream;
import java.util.ArrayList;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import packettracking.model.MACPacket;


public class Encoder {
	
	public Encoder(){
		
	}
	
	/**
	 * This class writes the collected packets to a file.
	 * 1. Pcap-File-Header
	 * 2. Pcap-Packet-Header
	 * 3. Packet 		(and back to step 2 for all packets)
	 */
	public void printPcapFile(ArrayList<MACPacket> packets){
		//Ask user if he wants to export the data to .pcap
		JFrame frame = new JFrame("The Question for export");		
		Object[] options = {"Yes", "No"};
		int n = JOptionPane.showOptionDialog(frame,
		"Do you want to export the logged data to .pcap?",
		"Important Question",
		JOptionPane.YES_NO_OPTION,
		JOptionPane.QUESTION_MESSAGE,
		null,     //do not use a custom Icon
		options,  //the titles of buttons
		options[0]); //default button title
	
		if(n == 0){
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
//			System.out.println("Collect packet #"+i+"...");
			outputArray = new byte[oldOutputArray.length+packets.get(i).toBytes().length];
			System.arraycopy(oldOutputArray, 0, outputArray, 0, oldOutputArray.length);
			System.arraycopy(packets.get(i).toBytes(), 0, outputArray, oldOutputArray.length, packets.get(i).toBytes().length);
			oldOutputArray = outputArray;
//			System.out.println("Packet #"+i+" done.");
		}
		
		System.out.println("All Packets ready to be saved.");
		
		//Open Dialog to save file
		FileDialog fd = new FileDialog(new Frame(), "Choose file to save converted Datalog.", FileDialog.SAVE);
		fd.setFile("output.pcap");
	    fd.setDirectory(".\\");
	    fd.setLocation(50, 50);
	    fd.setVisible(true);
	    
	    //Check for existence of the given address
	    if(!(fd.getFile() == null)){
	    	String address = fd.getDirectory() + fd.getFile();//System.getProperty("file.separator") + fd.getFile();
	    	//check ending of file (to be .pcap), otherwise fix it
		    if(!address.endsWith(".pcap")){
		    	address += ".pcap";
		    }
		    
			System.out.println("Writing to file "+ address + " ...");

			//try to save at given address
			try{
				FileOutputStream output = new FileOutputStream(address);
				output.write(outputArray);
				fd.dispose();
				System.out.println("Data to "+ address + " is succesfully saved.");
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
