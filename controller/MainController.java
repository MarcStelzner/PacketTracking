package packettracking.controller;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import packettracking.model.MACPacket;
import packettracking.model.MultihopPacketTrace;
import packettracking.model.Node;

import packettracking.testing.TestDataCreator;
import packettracking.utils.Calculator;
import packettracking.view.MainViewCLI;


public class MainController {
	
	ArrayList<MACPacket> packets;
	ArrayList<Node> nodes;
	ArrayList<MultihopPacketTrace> traces;
	
	public MainController(){		 
	}
	
	/**
	 * Main Method of the PacketTrackingSystem
	 * 
	 * Coordinating the flow of the program and printing out the results.
	 * TODO: When capabilities for input and output with user increase, functions should be transferred to new classes (Views)
	 */
	public void run(boolean testRun, int timeBetweenTraces){
		//set this variable to true for evaluation of testData
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();
		
		if(testRun){
			// runs for time evaluation:
			int[] traceNumbers = new int[]{100,1000,5000,10000,20000};
			int[] hops = new int[]{2,10,20};
			int[] seconds = new int[]{30,600,7200};
			
			//do some runs to warm up
			for(int l = 0; l < 50 ; l++){
				TestDataCreator creator = new TestDataCreator();
				creator.createTimeTraces(666, 7, 666);
				packets = creator.getPackets();
				Collections.sort(packets);
				nodes = creator.getNodes();
				//Get and Sort all packets to traces by double-linking between packets, nodes and traces
				TraceAnalyzer analyzer = new TraceAnalyzer(timeBetweenTraces);	
				Date before = new Date();
				traces = analyzer.setUpTraces(packets, nodes);
				//... and after analyze
				Date after = new Date();
				after.compareTo(before);
				int differenceInMS = (int)(after.getTime() - before.getTime()); 
				System.out.println("Iteration "+l+" takes: "+differenceInMS+" ms to calculate.");
			}
			
			
			//ALL runs
			for(int i = 0; i < traceNumbers.length; i++){
				for(int j = 0; j < hops.length; j++){
					for (int k = 0; k < seconds.length; k++){
						if(i == 4 && k == 0){
							//not 50k traces in 30 seconds ... overkill
							k++;
						}
						//10 runs for the average
						int averageTime = 0;
						for(int l = 0; l < 10 ; l++){
							System.gc();
							TestDataCreator creator = new TestDataCreator();
							creator.createTimeTraces(traceNumbers[i], hops[j], seconds[k]);
							packets = creator.getPackets();
							Collections.sort(packets);
							nodes = creator.getNodes();
							//Get and Sort all packets to traces by double-linking between packets, nodes and traces
							TraceAnalyzer analyzer = new TraceAnalyzer(timeBetweenTraces);	
							Date before = new Date();
							traces = analyzer.setUpTraces(packets, nodes);
							//... and after analyze
							Date after = new Date();
							after.compareTo(before);
							int differenceInMS = (int)(after.getTime() - before.getTime()); 
							System.out.println("Iteration "+l+" with "+traceNumbers[i]+" traces, "+hops[j]+" hops in "+seconds[k]+" seconds takes: "+differenceInMS+" ms to calculate.");
							averageTime += differenceInMS;
						}
						//get average:
						System.out.println("Average of 10 iterations with "+traceNumbers[i]+" traces, "+hops[j]+" hops in "+seconds[k]+" seconds is: "+averageTime/10);
						System.out.println("\n");
					}
				}
			}
			
			/*
			*/
/*
			int[] seconds = new int[]{1,10,30,60};
			int[] traceNumbers = new int[]{12,100,500,1000,4000};
			
			for(int i = 0; i < seconds.length; i++){
				for(int j = 0; j < traceNumbers.length; j++){
					//get all the needed testData
					TestDataCreator creator = new TestDataCreator();
//					ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesFull(seconds[i], traceNumbers[j]);	//WORKS
//					ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesFullFrag(seconds[i], traceNumbers[j]);  //TODO
					ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesFlow(seconds[i], traceNumbers[j]);	//WORKS
//					ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesStartEnd(seconds[i], traceNumbers[j]); //WORKS
//					ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesStartEndFrag(seconds[i], traceNumbers[j]); //TODO
//					ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesNothing(seconds[i], traceNumbers[j]); //WORKS
					packets = creator.getPackets();
					
					nodes = creator.getNodes();
					Collections.sort(packets);
					
					//Get and Sort all packets to traces by double-linking between packets, nodes and traces
					TraceAnalyzer analyzer = new TraceAnalyzer();	
					traces = analyzer.setUpTraces(packets, nodes);
					
					//Short Statuscheck
					System.out.println("\n//////////////////////////////////////////");
					System.out.println("Systemstatus after complete object creation: ");
					System.out.println("Number of Nodes: " + nodes.size());
					System.out.println("Number of Packets: " + packets.size());
					System.out.println("Number of Traces: " + traces.size());	
					System.out.println("//////////////////////////////////////////");
					
					//takes a lot of time:
					//comparing all packets of the traces for a match
					for(MultihopPacketTrace t : traces){
						MultihopPacketTrace matchingCompareTrace = null;
						for(MultihopPacketTrace ct: compareTraces){
							boolean traceMatching = true;
							if(t.getPacketList().size() == ct.getPacketList().size()){
								for(MACPacket p : t.getPacketList()){
									boolean packetMatchFound = false;
									for(MACPacket cp : ct.getPacketList()){
										//match to packet found ? good, continue with next packet
										if(cp.equals(p)){
											packetMatchFound = true;
											break;
										} //else ... continue search for a matching packet
									}
									//no match to a packet found ? search next trace, this trace is no match
									if(!packetMatchFound){	
										traceMatching = false;
										break;
									} //else ... see if all other packets also match
								}
							}
							else{
								traceMatching = false;
							}
							//all packets matched ?
							if(traceMatching == true){
								matchingCompareTrace = ct;
								break;
							} // else ... continue search for a matching trace
						}
						//if a compareTrace was found, remove it from list
						if(matchingCompareTrace != null){
							compareTraces.remove(matchingCompareTrace);
						} // else ... no matching trace was found, the analyzer did bad here
					}
					
					//Every trace left in compareTraces is an undetected trace
					System.out.println("Traces were sent in time interval of "+ seconds[i]+ " seconds.");
					System.out.println(traceNumbers[j]-compareTraces.size() + " of "+ traceNumbers[j] +" traces were correctly found.");
				}
			} /**/
			System.exit(1);
		} else {
			//At first always force to read some Data to Parse
			Decoder reader = new Decoder(); 
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
		
		//make it optional to print the Data to a pcap-File 
		if(!testRun){
			Encoder writer = new Encoder(); 
			writer.printPcapFile(packets);
		}
		
		//Get and Sort all packets to traces by double-linking between packets, nodes and traces
		TraceAnalyzer analyzer = new TraceAnalyzer(timeBetweenTraces);		
		traces = analyzer.setUpTraces(packets, nodes);
		
		//Short Statuscheck
		System.out.println("\n//////////////////////////////////////////");
		System.out.println("Systemstatus after complete object creation: ");
		System.out.println("Number of Nodes: " + nodes.size());
		System.out.println("Number of Packets: " + packets.size());
		System.out.println("Number of Traces: " + traces.size());	
		System.out.println("//////////////////////////////////////////");
		//now with all packets, nodes and PacketTraces set, sorted, originator/final destination found ...

//		//TODO: testing
//		for(MACPacket p: packets){
//			if(p.getOriginator() != null){
//				System.out.println(Calculator.bytesToHex(p.getOriginator()));
//			}
//		}
//		
//		for(Node n : nodes){
//			System.out.println(Calculator.bytesToHex(n.getNodeId()));
//		}
//		//TODO: testing
		
		//create a CLI to allow the user additional requests
		MainViewCLI cli = new MainViewCLI(this);
		cli.displayTraces(traces);
		cli.runCLI();

		System.exit(1);
	}
	
	
	
	public ArrayList<MultihopPacketTrace> traceByNode(String nodeId){
		ArrayList<MultihopPacketTrace> results = new ArrayList<MultihopPacketTrace>();
		byte[] nodeIdByte = Calculator.hexStringToByteArray(nodeId);
		for(MultihopPacketTrace t : traces){
			if(Arrays.equals(nodeIdByte,t.getSource().getNodeId())){
				results.add(t);
			}
		}	
		return results;
	}
	
	public ArrayList<MultihopPacketTrace> traceBetweenNodes(String node1, String node2){
		ArrayList<MultihopPacketTrace> results = new ArrayList<MultihopPacketTrace>();
		byte[] node1Byte = Calculator.hexStringToByteArray(node1);
		byte[] node2Byte = Calculator.hexStringToByteArray(node2);
		for(MultihopPacketTrace t : traces){
			//print alle traces between nodes
			if((Arrays.equals(node1Byte,t.getSource().getNodeId()) 
							&& Arrays.equals(node2Byte,t.getDestination().getNodeId()))
					|| (Arrays.equals(node2Byte,t.getSource().getNodeId()) 
							&& Arrays.equals(node1Byte,t.getDestination().getNodeId()))){
				results.add(t);
			// ... even broadcasts
			} else if ((Arrays.equals(node1Byte,t.getSource().getNodeId()) 
							&& Arrays.equals(new byte[]{(byte)255,(byte)255},t.getDestination().getNodeId()))
					|| (Arrays.equals(node2Byte,t.getSource().getNodeId()) 
							&& Arrays.equals(new byte[]{(byte)255,(byte)255},t.getDestination().getNodeId()))){
				for(Node i : t.getIntermediateNodes())
				{
					if(Arrays.equals(node1Byte,i.getNodeId())||Arrays.equals(node2Byte,i.getNodeId())){
						results.add(t);
					}
				}
			}
		}	
		return results;
	}
	
	public ArrayList<MultihopPacketTrace> traceByFlowLabel(String fl){
		ArrayList<MultihopPacketTrace> results = new ArrayList<MultihopPacketTrace>();
		int flowLabel = Integer.parseInt(fl);
		for(MultihopPacketTrace t : traces){
			if(flowLabel == t.getFlowLabel()){
				results.add(t);
			}
		}	
		return results;
	}
	
	/**
	 * List all traces where the reception was detected by the destination
	 * 
	 * @return
	 */
	public ArrayList<MultihopPacketTrace> finishedTraces(){
		ArrayList<MultihopPacketTrace> results = new ArrayList<MultihopPacketTrace>();
		for(MultihopPacketTrace t : traces){
			for(MACPacket p : t.getPacketList()){
				//if it matches, add to the list
				if((p.getDestinationNode().equals(t.getDestination()) &&  p.getLoggedAt().equals(t.getDestination())) 
						|| p.getDestinationNode().isBroadcast()){
					results.add(t);
					break;
				}
			}
		}	
		return results;
	}
	
	/**
	 * List all traces where the reception wasn't detected by the destination
	 * 
	 * @return
	 */
	public ArrayList<MultihopPacketTrace> unfinishedTraces(){
		//subtract unfinished traces from all traces
		ArrayList<MultihopPacketTrace> finished = finishedTraces();
		ArrayList<MultihopPacketTrace> results = new ArrayList<MultihopPacketTrace>();
		results.addAll(traces);
		results.removeAll(finished);
		return results;
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