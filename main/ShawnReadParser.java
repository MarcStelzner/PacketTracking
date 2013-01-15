package packettracking.main;
import java.awt.FileDialog;
import java.awt.Frame;
import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.util.ArrayList;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import packettracking.objects.Node;
import packettracking.objects.MACPacket;


public class ShawnReadParser {
	
	ArrayList<MACPacket> packets = new ArrayList<MACPacket>();
	ArrayList<Node> nodes = new ArrayList<Node>();
	
	/**
	 * @param args
	 */
	public ShawnReadParser(){		 
	}
	
	/**
	 * This Method reads the data from an file and creates packets as an object representation
	 * of the read data.
	 */
	public void readData(){
		//empty lists for packets and nodes
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();
		
		
		//empty Array for packets to check
		
		
		//Ask user if any protocol (only 6lowpan is supported at the moment) was used or just plain data

		JFrame frame = new JFrame("The Question for protocols");		
		Object[] options = {"Plain Payload", "Protocols"};
		int n = JOptionPane.showOptionDialog(frame,
		"To avoid false protocol dection:\n" +
		"Are any standardized protocols used in the datalog or just plain payloads send?\n" +
		"(In this version only 6LoWPAN is supported for packet tracking)",
		"Important Question",
		JOptionPane.YES_NO_OPTION,
		JOptionPane.QUESTION_MESSAGE,
		null,     //do not use a custom Icon
		options,  //the titles of buttons
		options[0]); //default button title
		
		//the information is used to recognize additional payload-data
		boolean protocols = false;
		if(n == 1){
			protocols = true;
		}

		//Dialog to load Data
	    FileDialog fd = new FileDialog(new Frame(), "Choose the Shawn-Datalog \"*.txt\" to read.", FileDialog.LOAD);
	    fd.setFile("*.txt");
	    fd.setDirectory(".\\");
	    fd.setLocation(50, 50);
	    fd.setVisible(true);
		//get address out of dialog
	    String address = fd.getDirectory() + fd.getFile();// + System.getProperty("file.separator") + fd.getFile();
		String line = "";
		
		//now create bytefield to read
		System.out.println("--- Going to read shawn wiselib-data ---");
		System.out.println("Opening " + address);
		//.. try to read the loggingfile from given address
		try{
		    BufferedReader reader = new BufferedReader(new FileReader(address));
			System.out.println(address + " found, reading contents.");
			//read file line by line
			int packetCount = 1;
			while ((line = reader.readLine()) != null) {				
				MACPacket tempPacket = new MACPacket(protocols);
				String[] tempLineString = line.split(";");
				String[] tempPayloadString = tempLineString[tempLineString.length-1].split(","); //last element is the payload
				
				//0.: mark packet for receiver or sender (false/0 = sender, true/1 = receiver)
				int tempInt = Integer.parseInt(tempLineString[0]);
				if(tempInt == 1){
					tempPacket.setReceived(true);
				} else {
					tempPacket.setReceived(false);
				}
				
				//1.: time in seconds
				tempPacket.setSeconds(parseStringToByteArray(tempLineString[1], 4));
				tempPacket.setMicroSeconds(new byte[]{0,0,0,0}); //TODO: read from somewhere in iSense-Message
				
				//2.: frame control (check length for 64 or 16 bit addressing) TODO: at the moment src and dest at same length
				boolean adressOf64Bit = false;
				if(Integer.parseInt(tempLineString[2]) > 2){
//					adressOf64Bit = true;   //  64 bit is strange at the moment with shawn (because it's always 32 bit)
				}
				if(adressOf64Bit){
					tempPacket.setFrameControl(new byte[]{(byte)0x01, (byte)0xcc}); 
				} else {
					tempPacket.setFrameControl(new byte[]{(byte)0x01, (byte)0x88}); 	
				}
				
				//3.: sequence number
				tempPacket.setSequenceNumber((byte)0); // TODO: no sequence number read at the moment
				
				//4.: source
				tempPacket.setSourcePAN(new byte[]{0,0}); // TODO: no PAN read at the moment
				byte[] tmpSource;
				if(adressOf64Bit){
					tmpSource = parseStringToByteArray(tempLineString[3], 8);
				} else {
					tmpSource = parseStringToByteArray(tempLineString[3], 2);
				}				
				
				//5.: destination 
				tempPacket.setDestinationPAN(new byte[]{0,0}); // TODO: no PAN read at the moment
				byte[] tmpDestination;
				if(adressOf64Bit){
					tmpDestination = parseStringToByteArray(tempLineString[4], 8);
				} else {
					tmpDestination = parseStringToByteArray(tempLineString[4], 2);
				}
				
				//6.: Create/Find node according to Source/Destination and double-link it to the packet
				boolean sourceFound = false;
				boolean destinationFound = false;
				for(Node node : nodes){
					if(node.getNodeId() == tmpDestination){
						destinationFound = true;
						//only add packet to the node where it is logged
						if(tempPacket.isReceived()){
							node.addReceivedPackets(tempPacket);
						}
						tempPacket.setDestinationNode(node);
					} 
					if(node.getNodeId() == tmpSource) {
						sourceFound = true;
						//only add packet to the node where it is logged
						if(!tempPacket.isReceived()){
							node.addSentPackets(tempPacket);
						}
						tempPacket.setSourceNode(node);
					}
				}
				if(!destinationFound){
					Node newNode = new Node(tmpDestination);
					nodes.add(newNode);
					if(tempPacket.isReceived()){
						newNode.addReceivedPackets(tempPacket);
					}
					tempPacket.setDestinationNode(newNode);
				}
				if(!sourceFound){
					Node newNode = new Node(tmpSource);
					nodes.add(newNode);
					if(!tempPacket.isReceived()){
						newNode.addSentPackets(tempPacket);
					}
					tempPacket.setSourceNode(newNode);
				}
				
				
				//7.: length of payload in bytes
				// need to add length of MAC-Header
				byte[] lengthArray = parseStringToByteArray(tempLineString[5], 4);
				byte macLength = 11;
				if(adressOf64Bit){
					macLength += 12; //length of destination and source each increased by 6
				}		
				//calculations for possible carry when adding macLength
				for(int i = lengthArray.length-1; i >= 0; i--){
					int checklength = lengthArray[i];
					//first correction from signed to unsigned
					if(checklength < 0 ){
						checklength=256+checklength;
					}
					//check for overflow
					if((checklength+macLength)>0xff){
						lengthArray[i] = (byte)(checklength+macLength);
						macLength = 1; // setting carry
					} else {
						lengthArray[i] = (byte)(checklength+macLength);
						break; //no more carry possible, so break
					}
				}
				tempPacket.setOriginalLength(lengthArray);
				tempPacket.setIncludingLength(lengthArray); //TODO: Noch von PCAP-MAX abhängig machen, falls Nachrichten über 2^16(65536) Byte lang
				
				//8.: payload
				tempPacket.setPayload(parsePayloadToByteArray(tempPayloadString));
				
				System.out.println("Flow Label: "+tempPacket.getFlowLabel());
				System.out.println("Datagram Size: "+tempPacket.getFragmentationSize());
				System.out.println("Datagram Tag: "+tempPacket.getFragmentationTag());
				
				//now add the packet to the Packetlist
				packets.add(tempPacket);
				
				System.out.println("Packet #"+packetCount+" is read.");
				packetCount ++;
			}
			System.out.println("All content successfully read and saved.");
			fd.dispose();
		} catch(Exception e) {
			System.out.println("Could not open File: " + e);
			System.exit(1);
		}
	}
	
	public ArrayList<MACPacket> getPackets(){
		return packets;
	}
	
	public ArrayList<Node> getNodes(){
		return nodes;
	}
	
	/**
	 * Parsing StringArray into an ByteArray
	 * @param toParse is the StringArray
	 * @param length of the StringArray
	 */
	private byte[] parsePayloadToByteArray(String[] toParse){
		byte[] bytes = new byte[toParse.length];
		//for each position of the string parse to byte
		//and put everything into one bytearray
		for(int i = 0; i < toParse.length; i++){
			bytes[i] = parseStringToByteArray(toParse[i], 1)[0];
		}
		return bytes;
	}
	
	/**
	 * Parsing String into an ByteArray
	 * @param toParse is the String
	 * @param length of the String in Bytes
	 */
	private byte[] parseStringToByteArray(String toParse, int length){
		//now parse String to long first ... careful: no more than length of 8(bytes) !
		long tempLong = Long.parseLong(toParse);
		//then parse long to an Array of Bytes
		byte[] bytes = ByteBuffer.allocate(8).putLong(tempLong).array();
		//now correct length
		if(bytes.length > length){
			byte[] tempBytes = new byte[length];
			for(int i = 0; i<tempBytes.length;i++){
				tempBytes[i] = bytes[i + (bytes.length - length)];
			}
			bytes = tempBytes;
		}
		return bytes;
	}
}
