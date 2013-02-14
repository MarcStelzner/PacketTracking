package packettracking.controller;
import java.awt.FileDialog;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;

import packettracking.model.MACPacket;
import packettracking.model.Node;
import packettracking.utils.Calculator;
import packettracking.view.DecoderView;


public class Decoder {
	
	ArrayList<MACPacket> packets = new ArrayList<MACPacket>();
	ArrayList<Node> nodes = new ArrayList<Node>();
	
	/**
	 * @param args
	 */
	public Decoder(){		 
	}
	
	/**
	 * This Method reads the data from an file and creates packets as an object representation
	 * of the read data.
	 */
	public void readData(){
		//empty lists for packets and nodes
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();

		DecoderView view = new DecoderView();
		
		boolean protocols = view.askForProtocols();

		//get address out of dialog
		FileDialog fd = view.askForDestination();
	    String address = fd.getDirectory() + fd.getFile();	
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
				//0. Size of Addresses TODO: elided
				//1. NodeID (Address)
				//2. X-Coordinate
				//3. Y-Coordinate
				//4. Z-Coordinate (seems unused so far)
				if(tempLineString.length == 4){
					parseNodeLocation(tempLineString);
				}
				
				//Length of 10 --> LoggedPacket
				//0. Size of Addresses TODO: elided
				//1. NodeID (Logging Node Address)
				//2. Time in Seconds
				//3. Time in Milliseconds
				//4. Time in Microseconds
				//5. Source
				//6. Destination
				//7. Link Metric
				//8. Size of Payload
				//9. Payload
				else if(tempLineString.length == 9){
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
//		//0. read size of the address
//		boolean adressOf64Bit = false;
//		if(Integer.parseInt(packetData[0]) > 2){
//			//adressOf64Bit = true;   //  64 bit is strange at the moment with shawn (because it's always 32 bit)
//		}
//
//		//1. read node id
//		byte[] tmpNodeId;
//		if(adressOf64Bit){
//			tmpNodeId = parseStringToByteArray(packetData[1], 8);
//		} else {
//			tmpNodeId = parseStringToByteArray(packetData[1], 2);
//		}
		
		byte[] tmpNodeId = Calculator.hexStringToByteArray(packetData[0]);
		
		boolean nodeFound = false;
		// 3./4./5. set coordinates		
		double x = Double.parseDouble(packetData[1]); //TODO: ehemals packetData[2]
		double y = Double.parseDouble(packetData[2]); //TODO: ehemalspacketData[3]
		double z = Double.parseDouble(packetData[3]); //TODO: ehemals packetData[4]
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
		
		//1.: Get the logging nodes address
		byte[] tmpNodeId = Calculator.hexStringToByteArray(tempLineString[0]);
		
		//2.: time in seconds
		tempPacket.setSeconds(Calculator.hexStringToByteArray(tempLineString[1]));
		
		//3.: additional milliseconds
		tempPacket.setMilliSeconds(Calculator.hexStringToByteArray(tempLineString[2])); 
		
		//4.: additional microseconds
		tempPacket.setMicroSeconds(Calculator.hexStringToByteArray(tempLineString[3])); 		
		
		//5.: source (and PAN)
		byte[] tmpSource = Calculator.hexStringToByteArray(tempLineString[4]);				
		
		//6.: destination (and PAN)
		byte[] tmpDestination = Calculator.hexStringToByteArray(tempLineString[5]);	
		
		//with information of logging node, src and dest. find the node or create a new one to link it to the packet
		updateNodes(tempPacket, tmpNodeId, tmpSource, tmpDestination);	
		
		//7.: now the link metric 
		int linkMetric = Calculator.byteArrayToInt(Calculator.hexStringToByteArray(tempLineString[6]));
		tempPacket.setLinkMetric(linkMetric);
		
		//8.: readlength of payload in bytes and set Pcap with it
		// need to add length of MAC-Header
		byte[] lengthArray = Calculator.hexStringToByteArray(tempLineString[7]);
		byte macLength = 11;	
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
		
		//9.: payload
		tempPacket.setPayload(Calculator.hexStringToByteArray(tempLineString[tempLineString.length-1]));
		
		//Pcap Header for PacketLength
		tempPacket.setOriginalLength(lengthArray);
		//includingLength should depend on maximum messagelength ... but size of maximum length is always 2^16(65536) Bytes
		tempPacket.setIncludingLength(lengthArray); 
		
		// --- "A maybe TODO": next parameters are not read, but set ---

		//set a default PAN four Source and destination
		tempPacket.setSourcePAN(new byte[]{0,0});
		tempPacket.setDestinationPAN(new byte[]{0,0});
		
		//MAC frame control (only address size is read)
		//tempPacket.setFrameControl(new byte[]{(byte)0x01, (byte)0xcc}); <<< for size of 64 bit
		tempPacket.setFrameControl(new byte[]{(byte)0x01, (byte)0x88}); 	
		
		//Sequence number
		tempPacket.setSequenceNumber((byte)0);
		
		//at last add the packet to the Packetlist
		packets.add(tempPacket);
	}
	
	
	/**
	 * Private method for readData for reading lines with packet-information
	 * 
	 * @param packetData
	 * @param protocols
	 */
/*	private void parsePacketALT(String[] packetData, boolean protocols){
		String[] tempLineString = packetData;
		MACPacket tempPacket = new MACPacket(protocols);
		
		//1. Size of Addresses
		boolean adressOf64Bit = false;
		if(Integer.parseInt(tempLineString[0]) > 2){
			adressOf64Bit = true;   //  64 bit is strange at the moment with shawn (because it's always 32 bit)
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
		tempPacket.setMilliSeconds(parseStringToByteArray(tempLineString[3], 2)); 
		
		//5.: additional microseconds
		tempPacket.setMicroSeconds(parseStringToByteArray(tempLineString[4], 2)); 		
		
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
		//TODO: alt
		//String[] tempPayloadString = tempLineString[tempLineString.length-1].split(","); //last element is the payload
		//tempPacket.setPayload(parsePayloadToByteArray(tempPayloadString));
		//neu
		tempPacket.setPayload(Calculator.hexStringToByteArray(tempLineString[tempLineString.length-1]));
		
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
	}*/
	
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
		
		//check if node is existing or needs to be created
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
				//if also logged here and node wasn't found, add logged at
				if(!loggedAtFound && !broadcast){
					tempPacket.setLoggedAt(newNode);
					loggedAtFound = true;
				}
			}
			tempPacket.setDestinationNode(newNode);
		}
		if(!sourceFound){
			Node newNode = new Node(tmpSource);
			nodes.add(newNode);
			if(!tempPacket.isReceived()){
				newNode.addSentPackets(tempPacket);
				//if also logged here and node wasn't found, add logged at
				if(!loggedAtFound){
					tempPacket.setLoggedAt(newNode);
					loggedAtFound = true;
				}
			}
			tempPacket.setSourceNode(newNode);
		}
		//only add new node on broadcast and when it's not sending the broadcast, otherwise loggedAt would not differ either from source or destination
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
}
