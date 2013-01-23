package packettracking.main;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
//import java.util.Comparator;
import java.util.HashSet;

import packettracking.objects.Node;
import packettracking.objects.MACPacket;
import packettracking.objects.MultihopPacketTrace;

import packettracking.support.Calculator;
import packettracking.testing.TestDataCreator;


public class Constructor {
	
	public Constructor(){		 
	}
	
	/**
	 * Main Method of the PacketTrackingSystem
	 */
	public void run(boolean testRun){	
		//set this variable to true for evaluation of testData
		ArrayList<MACPacket> packets = new ArrayList<MACPacket>();
		ArrayList<Node> nodes = new ArrayList<Node>();
		
		if(testRun){
			TestDataCreator creator = new TestDataCreator();
			creator.createData();
			packets = creator.getPackets();
			nodes = creator.getNodes();
		} else {
			//At first always force to read some Data to Parse //TODO: At the moment only for Shawn
			ReadParser reader = new ReadParser(); 
			reader.readData();
			packets = reader.getPackets();
			nodes = reader.getNodes();
		}
		//now we have lists of packets and nodes
		
		//check for existance of at least one packet before continueing
		if(packets.isEmpty()){
			System.out.println("Nothing to read, terminating...");
			//terminate without packets
			System.exit(1);
		}
		//be sure of the chronological part, so rearrange the packetorder
		Collections.sort(packets);
		
		//Get and Sort all packets to traces by double-linking between packets, nodes and traces
		ArrayList<MultihopPacketTrace> traces = setUpTraces(packets, nodes);
		
		//Short Statuscheck
		System.out.println("\n//////////////////////////////////////////");
		System.out.println("Systemstatus after complete object creation: ");
		System.out.println("Number of Nodes: " + nodes.size());
		System.out.println("Number of Packets: " + packets.size());
		System.out.println("Number of Traces: " + traces.size());	
		System.out.println("//////////////////////////////////////////");
		//now with all packets, nodes and PacketTraces set, sorted, originator/final destination found ... display the results
		//first a simple one, create text for nodes
		displayResultsAsText(traces);
		
		//at last, make it optional to print the Data to a pcap-File 
		if(!testRun){
			WriteParser writer = new WriteParser(); 
			writer.printPcapFile(packets);
		}
		System.exit(1);
	}
	
	private void displayResultsAsText(ArrayList<MultihopPacketTrace> traces){
		System.out.println("The analysis  of traces gave the following results:");
		int counter = 1;
		for(MultihopPacketTrace t : traces){
			System.out.println("Displaying Packet Trace #"+counter+": ");
			System.out.println(t.toString());
			System.out.println("\n");
			counter++;
		}
		
		System.out.println("//////////////////////////////////////////\n");
	}
	
	
	
	
	private ArrayList<MultihopPacketTrace> setUpTraces(ArrayList<MACPacket> packets, ArrayList<Node> nodes){
		ArrayList<MultihopPacketTrace> traces;
		//at first, create the initial traces by getting the packets
		traces = getTraces(packets);

		//Sort the packetlist of every trace chronologicaly
		sortTraces(traces);
		
		//Get all Nodes of a trace
		addNodesToTrace(traces);
		
		//Get originator nodes and final destination nodes
		setOriginatorAndDestinationForTrace(traces, nodes);
		
		//now the traces are configured !
		return traces;
	}
	
	private ArrayList<MultihopPacketTrace> getTraces(ArrayList<MACPacket> packets){
		ArrayList<MultihopPacketTrace> traces = new ArrayList<MultihopPacketTrace>();
		
		//1. Sort packets to stream by FlowLabel and Fragmentation Header
		ArrayList<MACPacket> checklaterFragmentation = new ArrayList<MACPacket>();
		//timeBetweenTraces is in seconds, TODO: maybe variable by user ? or even better adaptive to number of packets per node/minute
		//the time doubled is the secure distance between two traces with same flow label		
		int timeBetweenTraces = 15; 
		for(MACPacket p : packets){
			int tmpFlowLabel = p.getFlowLabel();
			int tmpFragmentationTag = p.getFragmentationTag();
			int tmpOccurrence = 0; //needed for flow label related parts
			if(tmpFlowLabel >= 0){
				boolean found = false;
				for(MultihopPacketTrace s : traces){
					if(s.getFlowLabel() == tmpFlowLabel){
						//check occurence-number of flow label
						//TODO: check could be improved, by taking in the flow label counter for a roundtrip 
						//at the moment "only" time based --> more than "timeBetweenStreams" seconds difference between the new message fl and
						//the last occurrence of the same fl in the stream --> search for the right stream or create a new one
						// (only check last time, because of chronological order !!)
						if(Calculator.byteArrayToInt(p.getSeconds()) > s.getLastTime()+timeBetweenTraces 
								|| (Calculator.byteArrayToInt(p.getSeconds()) == s.getLastTime()+timeBetweenTraces && Calculator.byteArrayToInt(p.getMilliSeconds()) >= s.getLastTimeMilliseconds()) ){
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
					MultihopPacketTrace tmpTrace = new MultihopPacketTrace(tmpFlowLabel, tmpOccurrence);
					traces.add(tmpTrace);
					tmpTrace.addPacket(p);
				}
			}
			//no flow label, but a fragmentation header ... keep the packet for later sorting
			else if (tmpFragmentationTag > 0){
				//this is done later because a first fragment may get delayed or even lost/not logged 
				//when checking later the first fragment might have appeared or another one showed up
				checklaterFragmentation.add(p);
			}
			//no flow label or fragmentation tag? just add to ordinary stream with 1 to 2 packets each
			else{
				boolean found = false;
				for(MultihopPacketTrace s : traces){  
					for(MACPacket sp : s.getPacketList()){
						//check for same destination, source, payloadsize and approximatly correct time
						//TODO: halved timeBetweenStreams because of more possible crossings ... useful ?
						//TODO: Problem, multihop won't work at all at the moment, because payload/source/destination changes
						int tmpTimeBetweenStreams = timeBetweenTraces;
						if(p.getDestinationNode().equals(sp.getDestinationNode())
								&& p.getSourceNode().equals(sp.getSourceNode())
								&& p.getPayloadSize() == sp.getPayloadSize()
								&& !(Calculator.byteArrayToInt(p.getSeconds()) > (Calculator.byteArrayToInt(sp.getSeconds())+tmpTimeBetweenStreams))
								&& !((Calculator.byteArrayToInt(p.getSeconds())+tmpTimeBetweenStreams) < Calculator.byteArrayToInt(sp.getSeconds()))){
							found = true;
							break;
						}
						
					}
					if(found){
						break;
					}
				}
			}
		}
		
		//now sort the packets with only a fragmentation header but no flow label to the according streams
		for(MACPacket p : checklaterFragmentation){
			int checkLaterTag = p.getFragmentationTag();
			boolean found = false;
			for(MultihopPacketTrace s : traces){
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
									&& !(Calculator.byteArrayToInt(p.getSeconds()) > (Calculator.byteArrayToInt(sp.getSeconds())+timeBetweenTraces))
									&& !((Calculator.byteArrayToInt(p.getSeconds())+timeBetweenTraces) < Calculator.byteArrayToInt(sp.getSeconds()))){
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
				MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
				traces.add(tmpTrace);
				tmpTrace.addPacket(p);
				p.setAccordingStream(tmpTrace);
			}
		}
		
		return traces;
	}
	
	private void sortTraces(ArrayList<MultihopPacketTrace> traces){
		//now back to chronological order with the packets of every trace
		for(MultihopPacketTrace s : traces){
			Collections.sort(s.getPacketList());
		}
	}
	
	private void addNodesToTrace(ArrayList<MultihopPacketTrace> traces){
		//get all node-appearances of a traces and put them into the "intermediateNodes"-List
		for(MultihopPacketTrace m : traces){
			ArrayList<Node> tmpNodeList = new ArrayList<Node>();
			for(MACPacket p : m.getPacketList()){
				tmpNodeList.add(p.getLoggedAt());
				tmpNodeList.add(p.getDestinationNode());
				tmpNodeList.add(p.getSourceNode());
			}
//			System.out.println(tmpNodeList.size());
//			System.out.println("Next PacketTrace: ");
//			for(Node n : tmpNodeList){
//				System.out.println("Node ");
//				for (byte b : n.getNodeId()) {
//					System.out.format("0x%x ", b);
//				}
//				System.out.println(" Logging Node ");
//				System.out.println("\n ");
//			}
			//elide all duplicates
			HashSet<Node> hs = new HashSet<Node>();
			hs.addAll(tmpNodeList);
			tmpNodeList.clear();
			tmpNodeList.addAll(hs);
			m.setIntermediateNodes(tmpNodeList);
//			System.out.println(tmpNodeList.size());
//			System.out.println("Next PacketTrace: ");
//			for(Node n : m.getIntermediateNodes()){
//				System.out.println("Node ");
//				for (byte b : n.getNodeId()) {
//					System.out.format("0x%x ", b);
//				}
//				System.out.println(" Logging Node ");
//				System.out.println("\n ");
//			}
		}
	}
	
	private void setOriginatorAndDestinationForTrace(ArrayList<MultihopPacketTrace> traces, ArrayList<Node> nodes){
		//set begin and "end" of all Traces
		for(MultihopPacketTrace m : traces){
			
			//first the originator ( ------ GET THE ORIGINATOR OF THE TRACE ------ )
			
			//first we get the FlowlabelId of the packet
			int possibleAddress = m.getFlowLabelId();
			//check messages with flow label 
			//(-BY USE OF FLOW LABEL-)
			if(possibleAddress >= 0){
				ArrayList<Node> foundNodes = new ArrayList<Node>();
				for(Node n : m.getIntermediateNodes()){
					int tmpCheckNodeId;
					if(n.getNodeId().length == 2){
						int tmpIntNodeId = Calculator.byteArrayToInt(n.getNodeId());	
						tmpCheckNodeId = tmpIntNodeId % 1024;
					} else {
						long tmpLongNodeId = Calculator.byteArrayToLong(n.getNodeId());
						tmpCheckNodeId = (int)(tmpLongNodeId % 1024);
					}
					//any node in the trace matching the searchid ?
					if(tmpCheckNodeId == possibleAddress){
						foundNodes.add(n);
					}
				}
				//best case, node is found ! 
				//(-BY ONLY FLOWLABEL-)
				if(foundNodes.size() == 1){
					//set node as source and remove it as intermediate node
					m.setSource(foundNodes.get(0));
					m.getIntermediateNodes().remove(foundNodes.get(0));
					foundNodes.get(0).addTraceByOrigin(m);
				}
				//no node found --> originatorPacket is not logged (shouldn't happen)
				//check if there is exactly one other node in the network matching it 
				//(-BY ONLY FLOWLABEL IN NETWORK & SUSPECTED PACKETS MISSED LOGGING-)
				else if(foundNodes.size() == 0){
					//look at all nodes for the same thing
					for(Node n : nodes){
						int tmpCheckNodeId;
						if(n.getNodeId().length == 2){
							int tmpIntNodeId = Calculator.byteArrayToInt(n.getNodeId());	
							tmpCheckNodeId = tmpIntNodeId % 1024;
						} else {
							long tmpLongNodeId = Calculator.byteArrayToLong(n.getNodeId());
							tmpCheckNodeId = (int)(tmpLongNodeId % 1024);
						}
						//any node in the trace matching the searchid ?
						if(tmpCheckNodeId == possibleAddress){
							foundNodes.add(n);
						}
					}
					//now check again for foundNodes
					//(-BY ONLY FLOWLABEL IN NETWORK & SUSPECTED PACKETS MISSED LOGGING & BY TIME-)
					if(foundNodes.size() == 0){
						//TODO: just a guess, should be wrong, but no better idea at the moment !
						m.setSource(m.getPacketList().get(0).getSourceNode());
						m.getIntermediateNodes().remove(m.getPacketList().get(0).getSourceNode());
						m.getPacketList().get(0).getSourceNode().addTraceByOrigin(m);
					} 
					//(-BY ONLY FLOWLABEL IN NETWORK & SUSPECTED PACKETS MISSED LOGGING)
					else if(foundNodes.size() == 1){
						m.setSource(foundNodes.get(0));
						foundNodes.get(0).addTraceByOrigin(m);
						//TODO: Maybe add a Phantom-Packet-Creation to make a connected graph ?
					}
					//(-BY ONLY FLOWLABEL IN NETWORK & SUSPECTED PACKETS MISSED LOGGING & BY TIME-)
					else if(foundNodes.size() >= 1){
						//TODO: just a guess, should be wrong, but no better idea at the moment !
						m.setSource(m.getPacketList().get(0).getSourceNode());
						m.getIntermediateNodes().remove(m.getPacketList().get(0).getSourceNode());
						m.getPacketList().get(0).getSourceNode().addTraceByOrigin(m);
					}
				}
				//bad, nodes with same hashed id ... get the first one (-BY MULTIPLE FLOWLABELS ADD TIME FACTOR-)
				else if(foundNodes.size() >= 1){
					boolean found = false;
					for(MACPacket p : m.getPacketList()){
						for(Node fn : foundNodes){
							if(p.getSourceNode().equals(fn)){
								m.setSource(fn);
								m.getIntermediateNodes().remove(fn);
								found = true;
								break; //no more search needed
							}
						}
						if(found){
							break; //no more search needed
						}
					}
				}
			}
			//no flow label
			//(-BY TIME-)
			else {
				//TODO: to get to testing, just take packet with first time,
				//--> can be improved, instead of taking the first one, search for the one receiving no message
				Node tempNode = m.getPacketList().get(0).getSourceNode();
				m.setSource(tempNode);
				m.getIntermediateNodes().remove(tempNode);
				tempNode.addTraceByOrigin(m);
			}
			
			
			
			
			
			//now get the end ( ------ GET THE DESTINATION OF THE TRACE ------ )
			//if one of the intermediate is broadcast --> destination is broadcast
			Node tempNode = m.getPacketList().get(m.getPacketList().size()-1).getDestinationNode();
			//(-BY BROADCAST-)
			if(tempNode.getNodeId().length == 2 && Arrays.equals(tempNode.getNodeId(), new byte[]{(byte) 0xFF,(byte) 0xFF}) 
					|| tempNode.getNodeId().length == 8 && Arrays.equals(tempNode.getNodeId(), new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF})){
				m.setDestination(tempNode);
				m.getIntermediateNodes().remove(tempNode);
				tempNode.addTraceByDestination(m);
			} 
			//(-BY NO BROADCAST AND TIME-)
			else {
				//TODO: to get to testing, just take packet with last time (no broadcast),
				//--> can be improved, instead of taking the last one, search for the one sending no message (without broadcast ... could work)
				m.setDestination(tempNode);
				m.getIntermediateNodes().remove(tempNode);
				tempNode.addTraceByDestination(m);
			}
		}
	}
}

// ---------------------------------------------------------------------------------
// ausgelagerte prints
// ---------------------------------------------------------------------------------

//print all nodes with size of received and sent packets

//for(Node n : nodes){
//	System.out.println("Node with received " + n.getReceivedPackets().size() +" packets and sent "+ n.getSentPackets().size() +" at Address:");
//	for (byte b : n.getNodeId()) {
//		System.out.format("0x%x ", b);
//	}
//	System.out.println("\n");
//}	




//print all received messages for node 1

//for(Node n : nodes){
//	if(Arrays.equals(n.getNodeId(),new byte[]{0,1})){
//		System.out.println("Received packets: ");
//		for(MACPacket p : n.getReceivedPackets()){
//			for (byte b : p.toBytes()) {
//				System.out.format("0x%x ", b);
//			}
//			System.out.println("\n ");
//		}
//		System.out.println("Sent packets: ");
//		for(MACPacket p : n.getSentPackets()){
//			for (byte b : p.toBytes()) {
//				System.out.format("0x%x ", b);
//			}
//			System.out.println("\n ");
//		}
//	}
//}




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




//test chronological sorting:

//print before:
//System.out.println(" ----------- before sorting ----------- ");
//for(MultihopPacketTrace s : streams){
//	System.out.println("Next PacketTrace: ");
//	for(MACPacket p : s.getPacketList()){
//		byte[] nodeId = p.getLoggedAt().getNodeId();
//		byte[] loggedTime = p.getSeconds();
//		System.out.println("Node ");
//		for (byte b : nodeId) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" at ");
//		for (byte b : loggedTime) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" with Data: ");
//		for (byte b : p.toBytes()) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println("\n ");
//	}
//}




//print after:

//System.out.println(" ----------- now after sorting ----------- ");
//for(MultihopPacketTrace s : streams){
//	System.out.println("Next PacketTrace: ");
//	for(MACPacket p : s.getPacketList()){
//		byte[] nodeId = p.getLoggedAt().getNodeId();
//		byte[] loggedTime = p.getSeconds();
//		System.out.println("Node ");
//		for (byte b : nodeId) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" at ");
//		for (byte b : loggedTime) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" with Data: ");
//		for (byte b : p.toBytes()) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println("\n ");
//	}
//}




//print the nodes:

//System.out.println(" ----------- the streams, their packets and their node ids ----------- ");
//for(MultihopPacketTrace s : streams){
//	System.out.println("Next PacketTrace: ");
//	for(MACPacket p : s.getPacketList()){
//		byte[] nodeId = p.getLoggedAt().getNodeId();
//		byte[] sourceId = p.getSourceNode().getNodeId();
//		byte[] destinationId = p.getDestinationNode().getNodeId();
//		System.out.println("Node ");
//		for (byte b : nodeId) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" Logging Node ");
//		for (byte b : sourceId) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" Source ");
//		for (byte b : destinationId) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" Destination ");
//		System.out.println("\n ");
//	}
//}




//testing the begging and end lists for traces from the nodes, try node with id 1 as origin

//ArrayList<MultihopPacketTrace> tmpTraces = nodes.get(2).getTracesByOrigin();
//for(MultihopPacketTrace t : tmpTraces){
//	System.out.println("Next PacketTrace: ");
//	for(MACPacket p : t.getPacketList()){
//		byte[] nodeId = p.getLoggedAt().getNodeId();
//		byte[] loggedTime = p.getSeconds();
//		System.out.println("Node ");
//		for (byte b : nodeId) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" at ");
//		for (byte b : loggedTime) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println(" with Data: ");
//		for (byte b : p.toBytes()) {
//			System.out.format("0x%x ", b);
//		}
//		System.out.println("\n ");
//	}
//}