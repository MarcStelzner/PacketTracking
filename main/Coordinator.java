package packettracking.main;
import java.util.ArrayList;

import packettracking.objects.Node;
import packettracking.objects.MACPacket;
import packettracking.objects.MultihopPacketTrace;


public class Coordinator {
	
	public Coordinator(){		 
	}
	
	/**
	 * Main Method of the PacketTrackingSystem
	 */
	public void run(){
		//At first always force to read some Data to Parse //TODO: At the moment only for Shawn
		ShawnReadParser reader = new ShawnReadParser(); 
		reader.readData();
		ArrayList<MACPacket> packets = reader.getPackets();
		ArrayList<Node> nodes = reader.getNodes();
		//maybe an additional backup-save before getting the streams ?
		
//print all nodes with size of received and sent packets
		
//		for(Node n : nodes){
//			System.out.println("Node with received " + n.getReceivedPackets().size() +" packets and sent "+ n.getSentPackets().size() +" at Address:");
//			for (byte b : n.getNodeId()) {
//				System.out.format("0x%x ", b);
//			}
//			System.out.println("\n");
//		}	

//print all received messages for node 1
		
//		for(Node n : nodes){
//			if(Arrays.equals(n.getNodeId(),new byte[]{0,1})){
//				System.out.println("Received packets: ");
//				for(MACPacket p : n.getReceivedPackets()){
//					for (byte b : p.toBytes()) {
//						System.out.format("0x%x ", b);
//					}
//					System.out.println("\n ");
//				}
//				System.out.println("Sent packets: ");
//				for(MACPacket p : n.getSentPackets()){
//					for (byte b : p.toBytes()) {
//						System.out.format("0x%x ", b);
//					}
//					System.out.println("\n ");
//				}
//			}
//		}
		
		
		//now we have a (chronological) list of packets and nodes
		
		//check for existance of packets in the read-in stuff
		if(packets.isEmpty()){
			System.out.println("Nothing to read, terminating...");
			//terminate with no packets
			System.exit(1);
		}
		
		//be sure of the chronological part and rearrange packetorder
		//TODO: Implement sorting algorithm if needed (the read in datalog from isense may be in wrong order)
		
		
		/*
		//testing the double linked characteristics (for own convinience)
		//set new microsecondstime to a testpacket from packetlist
		Packet testPacket = packets.get(5);
		System.out.println("Old microseconds: "+testPacket.getMicroSeconds()[0]);
		testPacket.setMicroSeconds(new byte[]{2,0,0,0});
		System.out.println("New microseconds: "+testPacket.getMicroSeconds()[0]);
		
		// get the node from the testpacket
		Node testNode = testPacket.getAccordingNode();
		
		//get the packet back from the node and read the microseconds
		if(testPacket.isReceived()){
			for(Packet p : testNode.getReceivedPackets()){
				if(p.equals(testPacket)){
					System.out.println("Packet from node in microseconds new: "+p.getMicroSeconds()[0]);
				}
			}
		} else {
			for(Packet p : testNode.getSentPackets()){
				if(p.equals(testPacket)){
					System.out.println("Packet from node in microseconds new: "+p.getMicroSeconds()[0]);
				}
			}
		}
		
		//at last, get every node and check every packet for a match
		for(Node n : nodes){
			for(Packet p : n.getReceivedPackets()){
				if(p.getMicroSeconds()[0] == (byte)2){
					System.out.println("Packet directly nodelist in microseconds new: "+p.getMicroSeconds()[0]);
				}
			}
			for(Packet p : n.getSentPackets()){
				if(p.getMicroSeconds()[0] == (byte)2){
					System.out.println("Packet directly nodelist in microseconds new: "+p.getMicroSeconds()[0]);
				}
			}
		} */
		
		/*
		 * Sort all packets to Streams by double-linking between packet and stream
		 */
		
		ArrayList<MultihopPacketTrace> streams = getStreams(packets);
		
		System.out.println("////////////////////////////////////////////////////////");
		System.out.println("Number of Nodes: " + nodes.size());
		System.out.println("Number of Packets: " + packets.size());
		System.out.println("Number of Streams: " + streams.size());
		System.out.println("////////////////////////////////////////////////////////");		
		

		// TODO:
		// - get whole packet transfer between two nodes (on mac-level and on "flow label/datagram tag"-6lowpan-level)
		// 		---> TODO: sort streams ?!? ---> at least find out the source and the destination
		
		//at last, make it optional to print the Data to a pcap-File
		WriteParser writer = new WriteParser(); 
		writer.printPcapFile(packets);
		System.exit(1);
	}
	
	
	
	

	
	private ArrayList<MultihopPacketTrace> getStreams(ArrayList<MACPacket> packets){
		ArrayList<MultihopPacketTrace> streams = new ArrayList<MultihopPacketTrace>();
		
		//1. Sort packets to stream by FlowLabel and Fragmentation Header
		ArrayList<MACPacket> checklaterFragmentation = new ArrayList<MACPacket>();
		//timeBetweenStreams is in seconds, TODO: maybe variable by user ? 
		//the time doubled is the secure distance between two streams with same flow label		
		int timeBetweenStreams = 15; 
		for(MACPacket p : packets){
			int tmpFlowLabel = p.getFlowLabel();
			int tmpFragmentation = p.getFragmentationTag();
			int tmpOccurrence = 0; //needed for flow label related parts
			if(tmpFlowLabel >= 0){
				boolean found = false;
				for(MultihopPacketTrace s : streams){
					if(s.getFlowLabel() == tmpFlowLabel){
						//check occurence-number of flow label
						//TODO: check could be improved, by taking in the flow label counter for a roundtrip 
						//at the moment "only" time based --> more than "timeBetweenStreams" seconds difference between the new message fl and
						//the last occurrence of the same fl in the stream --> search for the right stream or create a new one
						// (only check last time, because of chronological order !!)
						if(byteArrayToInt(4,p.getSeconds()) > s.getLastTime()+timeBetweenStreams 
								|| (byteArrayToInt(4,p.getSeconds()) == s.getLastTime()+timeBetweenStreams && byteArrayToInt(4,p.getMicroSeconds()) >= s.getLastTimeMicroseconds()) ){
							//look for another stream (next occurrence) or create a new one
							tmpOccurrence ++;
						}
						else{
							//if in the right occurrence
							s.addPacket(p);
							found = true;
						}
					}
				}
				if(!found){
					MultihopPacketTrace tmpStream = new MultihopPacketTrace(tmpFlowLabel, tmpOccurrence);
					streams.add(tmpStream);
					tmpStream.addPacket(p);
				}
			}
			//no flow label, but a fragmentation header ... keep the packet for later sorting
			else if (tmpFragmentation > 0){
				//this is done later because a first fragment may get delayed or even lost/not logged 
				//when checking later the first fragment might have appeared or another one showed up
				checklaterFragmentation.add(p);
			}
			//no flow label or fragmentation tag? just add to ordinary stream with 1 to 2 packets each
			else{
				boolean found = false;
				for(MultihopPacketTrace s : streams){   //TODO: BIG TODO, open wound here ... no concentrating possible
					//... TODO: do some stuff for packets with no flow label and no fragmentation header to at least bring two packets together
					if(p.getDestinationNode().equals(s.getDestinationNode())
							&& p.getSourceNode().equals(s.getSourceNode())
							&& !(byteArrayToInt(4,p.getSeconds()) > (byteArrayToInt(4,s.getSeconds())+timeBetweenStreams))
							&& !((byteArrayToInt(4,p.getSeconds())+timeBetweenStreams) < byteArrayToInt(4,s.getSeconds()))){
						
					}
				}
				//TODO: use milliseconds !
			}
		}
		
		//now sort the packets with only a fragmentation header but no flow label to the according streams
		for(MACPacket p : checklaterFragmentation){
			int checkLaterTag = p.getFragmentationTag();
			boolean found = false;
			for(MultihopPacketTrace s : streams){
				for(Integer i : s.getFragmentationTags()){
					//if the tag of the packet is found in a stream ...
					if(checkLaterTag == i){
						//... there's the problem of identical tags left, so we have to check for matching packet
						// from the stream ...
						for(MACPacket sp : s.getPacketList()){
							int streamPacketTag = sp.getFragmentationTag();
							//if tag, sender, receiver, datagramsize, datagram tag and approximately the time matches it's okay
							//TODO: possible problem: on multihop it won't work with one of first fragment missing, all other fragments on this hop are unconnected
							//           ---> but it's not easy anyway with first fragment missing, after IP-Hop -> new tag, only mesh-under could be solved
							if(streamPacketTag == checkLaterTag && p.getDestinationNode().equals(sp.getDestinationNode())
									&& p.getSourceNode().equals(sp.getSourceNode()) && p.getFragmentationSize() == sp.getFragmentationSize()
									&& !(byteArrayToInt(4,p.getSeconds()) > (byteArrayToInt(4,sp.getSeconds())+timeBetweenStreams))
									&& !((byteArrayToInt(4,p.getSeconds())+timeBetweenStreams) < byteArrayToInt(4,sp.getSeconds()))){
								found = true;
								s.addPacket(p);
								p.setAccordingStream(s);
								break; //get to next packet, no duplicates of packets
							}
						}
					}
					if(found){
						break; //... get to next packet
					}
				}
				if(found){
					break; //... get to next packet
				}	
			}
			//no matching packet with tag found ? --> create new stream
			if(!found){
				MultihopPacketTrace tmpStream = new MultihopPacketTrace();
				streams.add(tmpStream);
				tmpStream.addPacket(p);
				p.setAccordingStream(tmpStream);
			}
		}
		
		return streams;
	}
	
	
	/**
	 * This Method turns bytearrays of a maximum length of 4 into integer
	 * 
	 * @param length
	 * @param array
	 * @return
	 */
	private int byteArrayToInt(int length, byte[] array){
		int newInt = 0;
		if(length > 4){
			System.out.println("Bytearray is too large with a size of "+length+". Only a length of 4 is possible (32 bit for int). Last "+(length-4)+" bytes will be ignored." );
			length = 4;
		}
		else{
			for(int i = 0 ; i < length ; i++){
				newInt += (array[i] << ((length-1-i)*8)) & 0xFF;
			}
		}
		return newInt;
	}
}
