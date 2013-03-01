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

/**
 * The Decoder-class reads logged packet-information from an inputfile and creates the
 * first representation for logs and nodes as an object database
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-15        
 */
public class Decoder {
	
	ArrayList<MACPacket> packets = new ArrayList<MACPacket>();
	ArrayList<Node> nodes = new ArrayList<Node>();
	
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
		
		//checks for the use of standardized protocols
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
				//1. NodeID (Address)
				//2. X-Coordinate
				//3. Y-Coordinate
				//4. Z-Coordinate (seems unused so far)
				if(tempLineString.length == 4){
					try{
						parseNodeLocation(tempLineString);
					} catch(Exception e){
						System.out.println("Node Location has bad format.");
					}
				}
				
				//Length of 10 --> LoggedPacket
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
					try{
						parsePacket(tempLineString, protocols);
						System.out.println("Packet #"+packetCount+" is read.");
					} catch(Exception e){
						System.out.println("Corrupt protocol information in packet #"+packetCount+". Trying to parse only MAC.");
						try{
							parsePacket(tempLineString, false);
							System.out.println("Packet #"+packetCount+" is read.");
						} catch(Exception e2){
							System.out.println("Packet #"+packetCount+" has bad format and is not read.");
						}
					}
					packetCount ++;
				}
				//otherwise ---> Error
				else {
					System.out.println("Corrupt line, wrong fieldcount. Continue with next line.");
				}
			}
			System.out.println(packets.size()+" packets successfully read and saved.");
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
		byte[] tmpNodeId = Calculator.hexStringToByteArray(packetData[0]);
		
		boolean nodeFound = false;
		// 3./4./5. set coordinates		
		double x = Double.parseDouble(packetData[1]);
		double y = Double.parseDouble(packetData[2]);
		double z = Double.parseDouble(packetData[3]);
		for(Node node : nodes){
			//check for existance of the nodeId in the nodelist
			if(Arrays.equals(node.getNodeId(),tmpNodeId)){//node.getNodeId().equals(tmpNodeId)){
				//update coords
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
		tempPacket.setPayload(Calculator.hexStringToByteArray(tempLineString[tempLineString.length-1].trim()));
		
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
					
	/**
	 * Get-method for the MainController to access the read packets
	 * 
	 * @return packets
	 */
	public ArrayList<MACPacket> getPackets(){
		return packets;
	}
	
	/**
	 * Get-method for the MainController to access the created nodes
	 * 
	 * @return nodes
	 */
	public ArrayList<Node> getNodes(){
		return nodes;
	}
}
