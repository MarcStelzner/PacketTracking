package packettracking.main;
import java.awt.FileDialog;
import java.awt.Frame;
import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

import packettracking.objects.Node;
import packettracking.objects.MACPacket;


public class ReadParser {
	
	ArrayList<MACPacket> packets = new ArrayList<MACPacket>();
	ArrayList<Node> nodes = new ArrayList<Node>();
	
	/**
	 * @param args
	 */
	public ReadParser(){		 
	}
	
	/**
	 * This Method reads the data from an file and creates packets as an object representation
	 * of the read data.
	 */
	public void readData(){
		//empty lists for packets and nodes
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();

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
		System.out.println("--- Starting to read shawn wiselib-data ---");
		System.out.println("Opening " + address + " ... ");
		//.. try to read the loggingfile from given address
		try{
		    BufferedReader reader = new BufferedReader(new FileReader(address));
			System.out.println(address + " found.\nReading contents ...");
			int packetCount = 1;
			//read file line by line			
			while ((line = reader.readLine()) != null) {		
				String[] tempLineString = line.split(";");
				
				
				//check length(Count of ";"+1) for Informationtype:
				
				//Length of 5 --> NodeLocation
				//1. Size of Addresses
				//2. NodeID (Address)
				//3. X-Coordinate
				//4. Y-Coordinate
				//5. Z-Coordinate (seems unused so far)
				if(tempLineString.length == 5){
					parseNodeLocation(tempLineString);
				}
				
				//Length of 10 --> LoggedPacket
				//1. Size of Addresses
				//2. NodeID (Logging Node Address)
				//3. Time in Seconds
				//4. Time in Milliseconds
				//5. Time in Microseconds
				//6. Source
				//7. Destination
				//8. Link Metric
				//9. Size of Payload
				//10. Payload
				else if(tempLineString.length == 10){
					parsePacket(tempLineString, protocols);
					//System.out.println("Packet #"+packetCount+" is read.");
					packetCount ++;
				}
				//otherwise ---> Error
				else {
					System.out.println("Corrupt line of wrong fieldcount. Continue with next line.");
				}
			}
			System.out.println("All content successfully read and saved.");
			fd.dispose();
		} catch(Exception e) {
			System.out.println("Could not open File: " + e);
			System.exit(1);
		}
	}
		
	/**
	 * Private method for readData for reading lines updating the nodeLocation
	 * 
	 * @param packetData
	 */
	private void parseNodeLocation(String[] packetData){
		//1. read size of the address
		boolean adressOf64Bit = false;
		if(Integer.parseInt(packetData[0]) > 2){
			//adressOf64Bit = true;   //  64 bit is strange at the moment with shawn (because it's always 32 bit)
		}

		//2. read node id
		byte[] tmpNodeId;
		if(adressOf64Bit){
			tmpNodeId = parseStringToByteArray(packetData[1], 8);
		} else {
			tmpNodeId = parseStringToByteArray(packetData[1], 2);
		}
		boolean nodeFound = false;
		// 3./4./5. set coordinates		
		double x = Double.parseDouble(packetData[2]);
		double y = Double.parseDouble(packetData[3]);
		double z = Double.parseDouble(packetData[4]);
		for(Node node : nodes){
			//check for existance of the nodeId in the nodelist
			if(Arrays.equals(node.getNodeId(),tmpNodeId)){//node.getNodeId().equals(tmpNodeId)){
				//update coords
				//--> TODO: Expansion for moving nodes possible by making key-value pairs of time and vectors
				nodeFound = true;
				node.setCoords(x, y, z);
				break;
			} 
		}
		if(!nodeFound){
			Node tempNode = new Node(tmpNodeId, x, y, z);
			nodes.add(tempNode);
		}		
	}
	
	/**
	 * Private method for readData for reading lines with packet-information
	 * 
	 * @param packetData
	 * @param protocols
	 */
	private void parsePacket(String[] packetData, boolean protocols){
		String[] tempLineString = packetData;
		MACPacket tempPacket = new MACPacket(protocols);
		
		//1. Size of Addresses
		boolean adressOf64Bit = false;
		if(Integer.parseInt(tempLineString[0]) > 2){
//			adressOf64Bit = true;   //  64 bit is strange at the moment with shawn (because it's always 32 bit)
		}
		
		//2.: Get the logging nodes address
		byte[] tmpNodeId;
		if(adressOf64Bit){
			tmpNodeId = parseStringToByteArray(tempLineString[1], 8);
		} else {
			tmpNodeId = parseStringToByteArray(tempLineString[1], 2);
		}
		
		//3.: time in seconds
		tempPacket.setSeconds(parseStringToByteArray(tempLineString[2], 4));
		
		//4.: additional milliseconds
		tempPacket.setMilliSeconds(parseStringToByteArray(tempLineString[3], 4)); 
		
		//5.: additional microseconds
		tempPacket.setMicroSeconds(parseStringToByteArray(tempLineString[4], 4)); 		
		
		//6.: source (and PAN)
		byte[] tmpSource;
		if(adressOf64Bit){
			tmpSource = parseStringToByteArray(tempLineString[5], 8);
		} else {
			tmpSource = parseStringToByteArray(tempLineString[5], 2);
		}				
		
		//7.: destination (and PAN)
		byte[] tmpDestination;
		if(adressOf64Bit){
			tmpDestination = parseStringToByteArray(tempLineString[6], 8);
		} else {
			tmpDestination = parseStringToByteArray(tempLineString[6], 2);
		}
		
		//with information of logging node, src and dest. find the node or create a new one to link it to the packet
		updateNodes(tempPacket, tmpNodeId, tmpSource, tmpDestination);	
		
		//8.: now the link metric 
		int linkMetric = Integer.parseInt(tempLineString[7]);
		tempPacket.setLinkMetric(linkMetric);
		
		//9.: readlength of payload in bytes and set Pcap with it
		// need to add length of MAC-Header
		byte[] lengthArray = parseStringToByteArray(tempLineString[8], 4);
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
		
		//10.: payload
		String[] tempPayloadString = tempLineString[tempLineString.length-1].split(","); //last element is the payload
		tempPacket.setPayload(parsePayloadToByteArray(tempPayloadString));
		
//		System.out.println("Flow Label: "+tempPacket.getFlowLabel());
//		System.out.println("Datagram Size: "+tempPacket.getFragmentationSize());
//		System.out.println("Datagram Tag: "+tempPacket.getFragmentationTag());
		
		//Pcap Header for PacketLength
		tempPacket.setOriginalLength(lengthArray);
		//includingLength should depend on maximum messagelength ... but size of maximum length is always 2^16(65536) Bytes
		tempPacket.setIncludingLength(lengthArray); 
		
		// --- "A maybe TODO": next parameters are not read, but set ---

		//set a default PAN four Source and destination
		tempPacket.setSourcePAN(new byte[]{0,0});
		tempPacket.setDestinationPAN(new byte[]{0,0});
		
		//MAC frame control (only address size is read)
		if(adressOf64Bit){
			tempPacket.setFrameControl(new byte[]{(byte)0x01, (byte)0xcc}); 
		} else {
			tempPacket.setFrameControl(new byte[]{(byte)0x01, (byte)0x88}); 	
		}
		
		//Sequence number
		tempPacket.setSequenceNumber((byte)0);
		

		//at last add the packet to the Packetlist
		packets.add(tempPacket);
	}
	
	/**
	 * This method updates the node-list for the parsePacket() if it is necessary
	 * 
	 * @param tempPacket
	 * @param tmpNodeId
	 */
	private void updateNodes(MACPacket tempPacket, byte[] tmpNodeId, byte[] tmpSource, byte[] tmpDestination){	
		boolean sourceFound = false;
		boolean destinationFound = false;
		boolean loggedAtFound = false;
		
		//check if source matches the id --> packet send, otherwise it's received
		// (does not work the other way round, because it's a broadcast)
		if(Arrays.equals(tmpNodeId, tmpSource)){
			tempPacket.setReceived(false);
		}
		else{
			tempPacket.setReceived(true);
		}
		
		//check if message is broadcastmessage
		boolean broadcast = true;
		for(int i = 0; i < tmpDestination.length ; i++){
			if(!(((byte)tmpDestination[i]) == ((byte)0xFF))){
				broadcast = false;
				break;
			}
		}
		
		for(Node node : nodes){
			//check for the logged location (never broadcast here)
			if(Arrays.equals(node.getNodeId(), tmpNodeId)){
				loggedAtFound = true;
				tempPacket.setLoggedAt(node);
				//only add packet to the node where it is logged
				if(tempPacket.isReceived()){
					node.addReceivedPackets(tempPacket);
				} else {
					node.addSentPackets(tempPacket);
				}
				//System.out.println("!!!!!! loggedAt found !!!!!!");
			}
			//check for destination
			if(Arrays.equals(node.getNodeId(), tmpDestination)){//node.getNodeId().equals(tmpDestination)){
				destinationFound = true;
				tempPacket.setDestinationNode(node);
				//System.out.println("!!!!!! destination found !!!!!!");
			} 
			//check for source
			if(Arrays.equals(node.getNodeId(), tmpSource)){//node.getNodeId().equals(tmpSource)) {
				sourceFound = true;
				tempPacket.setSourceNode(node);
				//System.out.println("!!!!!! source found !!!!!!");
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
		//only add new node on broadcast, otherwise loggedAt would not differ either from source or destination
		if(!loggedAtFound && broadcast){
			Node newNode = new Node(tmpNodeId);
			nodes.add(newNode);
			tempPacket.setLoggedAt(newNode);
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
