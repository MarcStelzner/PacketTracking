package packettracking.controller;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import packettracking.model.MACPacket;
import packettracking.model.MultihopPacketTrace;
import packettracking.model.Node;

import packettracking.support.Calculator;
import packettracking.testing.TestDataCreator;
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
	public void run(boolean testRun){	
		//set this variable to true for evaluation of testData
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();
		
		if(testRun){
			TestDataCreator creator = new TestDataCreator();
			creator.createData();
			packets = creator.getPackets();
			nodes = creator.getNodes();
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
		TraceAnalyzer analyzer = new TraceAnalyzer();
		traces = analyzer.setUpTraces(packets, nodes);
		
		//Short Statuscheck
		System.out.println("\n//////////////////////////////////////////");
		System.out.println("Systemstatus after complete object creation: ");
		System.out.println("Number of Nodes: " + nodes.size());
		System.out.println("Number of Packets: " + packets.size());
		System.out.println("Number of Traces: " + traces.size());	
		System.out.println("//////////////////////////////////////////");
		//now with all packets, nodes and PacketTraces set, sorted, originator/final destination found ...
		
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