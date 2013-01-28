package packettracking.testing;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;

import org.jgrapht.DirectedGraph;
import org.jgrapht.ext.DOTExporter;
import org.jgrapht.ext.VertexNameProvider;
import org.jgrapht.graph.DefaultDirectedGraph;

import packettracking.model.MACPacket;
import packettracking.model.Node;
import packettracking.support.Calculator;


public class TestDataCreator {
	
	ArrayList<MACPacket> packets = new ArrayList<MACPacket>();
	ArrayList<Node> nodes = new ArrayList<Node>();
	
	/**
	 * @param args
	 */
	public TestDataCreator(){		 
	}
	
	/**
	 * This main method uses JGraphT to create a graph and translate it's contents into packets and nodes
	 */
	public void createData(){
		//empty lists for packets and nodes
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();

		
//		DirectedGraph<Node, DefaultEdge> testGraph = new DefaultDirectedGraph<Node, DefaultEdge>(DefaultEdge.class);
//		ClassBasedVertexFactory<Node> factory = new ClassBasedVertexFactory<Node>(Node.class);
//		RandomGraphGenerator<Node, DefaultEdge> generator = new RandomGraphGenerator<Node, DefaultEdge>(9, 7) ;
//		generator.generateGraph(testGraph, factory, null);

		
		//in dieser einstellung ca. ne minute
		int numberOfNodes = 500;
		int numberOfTraces = 10;
	
		int minTraceLength = 7; //minTraceLength MUST be less than numberOfNodes
		int maxTraceLength = 8; //maxTraceLength MUST be less than numberOfNodes

		int minTimeVariety = 0; //starting time
		int maxTimeVariety = 3600;
		int minNetworkDelay = 0; //simulated delay in the network
		int maxNetworkDelay = 5; 
		int minTimeBeforeForwarding = 0; //time before forwarding to next address on trace
		int maxTimeBeforeForwarding = 8; 
		
		
		maxTraceLength++;
		maxTimeVariety++;
		maxNetworkDelay++;
		maxTimeBeforeForwarding++;
		//easy part, create the nodes
		for(int i = 0; i < numberOfNodes;i++){
			byte[] tmpNodeId = new byte[2];
			for(int j = 0; j < tmpNodeId.length;j++){
				double randomDouble = Math.random()*256.0;
				tmpNodeId[j]= (byte)(int)randomDouble;
			}
			double x = Math.random()*10;
			double y = Math.random()*10;
			double z = 0;
			//check for doubled address
			boolean existing = false;
			for(Node n : nodes){
				if(Arrays.equals(n.getNodeId(),tmpNodeId)){
					existing = true;
					i--;
				}
			}
			//add new node to graph and nodelist
			if(!existing){
				Node tmpNode = new Node(tmpNodeId,x,y,z);
				nodes.add(tmpNode);
			}
		}
		
		//A List of packetlists for graphs to create
		ArrayList<ArrayList<MACPacket>> graphPacketsLists = new ArrayList<ArrayList<MACPacket>>(); 		
		
		
		//more complex part: create traces
		for(int i = 0; i < numberOfTraces;i++){
			//use up to 9 hops
			int hops = ((int)(Math.random()*(maxTraceLength-minTraceLength)))+minTraceLength; 
			//a list of nodes left to use in the trace
			ArrayList<Node> nodesLeft = new ArrayList<Node>();
			nodesLeft.addAll(nodes);
			Node actualPosition = nodesLeft.remove((int)(Math.random()*nodesLeft.size()));
			int timeCounter = (int)(Math.random()*(maxTimeVariety-minTimeVariety))+minTimeVariety; //starting time of each trace between 0 and 10
			//generate a flowLabel
			//first the id from the nodeid/address between 0 and 1024
			for (byte b : actualPosition.getNodeId()) {
				System.out.format("0x%x ", b);
			}
			int flowLabelId = (Calculator.byteArrayToInt(actualPosition.getNodeId())) % 1024;
			System.out.println(Calculator.byteArrayToInt(actualPosition.getNodeId()));
			//now a counter-number for the label
			int flowLabelCounter = (int)(Math.random()*1024);
			int flowLabel = (flowLabelId << 10) + flowLabelCounter;
			byte[] flowLabelArray = ByteBuffer.allocate(4).putInt(flowLabel).array(); //array with one field to much ... ignore it
//			System.out.println("ID: "+flowLabelId + "  Counter: "+flowLabelCounter+"  Complete: "+flowLabel);
//			for (byte b : flowLabelArray) {
//				System.out.format("0x%x ", b);
//			}
//			System.out.println();
			//just ANY example data
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			//now use flowLabel to change the payload at position 2,3 and 4
			payload[2] = flowLabelArray[1];
			payload[3] = flowLabelArray[2];
			payload[4] = flowLabelArray[3];
			
			ArrayList<MACPacket> graphPacketList = new ArrayList<MACPacket>(); //this list is only for the graph
			
			for(int j = 0; j < hops; j++){
				//get next hop, it's a new one
				Node nextPosition = nodesLeft.remove((int)(Math.random()*nodesLeft.size()));
				//create info for the two packets
				MACPacket p = new MACPacket(true);
				p.setSourceNode(actualPosition);
				p.setDestinationNode(nextPosition);
				p.setPayload(payload);
				byte[] seconds = ByteBuffer.allocate(4).putInt(timeCounter).array();
				p.setSeconds(seconds);
				p.setMicroSeconds(new byte[]{0,0,0,0});
				p.setMilliSeconds(new byte[]{0,0,0,0});
				p.setLoggedAt(actualPosition);
				
				//adding packet one (sent packet)
				actualPosition.addSentPackets(p);
				packets.add(p);
				graphPacketList.add(p);
				
				//changing time for packet two
				timeCounter += (int)(Math.random()*(maxNetworkDelay-minNetworkDelay))+minNetworkDelay;
				p = new MACPacket(true);
				p.setSourceNode(actualPosition);
				p.setDestinationNode(nextPosition);
				p.setPayload(payload);
				seconds = ByteBuffer.allocate(4).putInt(timeCounter).array();
				p.setSeconds(seconds);
				p.setMicroSeconds(new byte[]{0,0,0,0});
				p.setMilliSeconds(new byte[]{0,0,0,0});
				p.setLoggedAt(nextPosition);
				
				//... and adding it (received packet)
				nextPosition.addReceivedPackets(p);
				packets.add(p);
				
				//settings for the next 2 packets of the trace
				actualPosition = nextPosition;
				timeCounter += (int)(Math.random()*(maxTimeBeforeForwarding-minTimeBeforeForwarding))+minTimeBeforeForwarding;
			}
			graphPacketsLists.add(graphPacketList);
		}
		
		

		
		//so far so good ... 20 random nodes, at random positions, using 7 traces
		

		

		
		// now create graphs for each trace
		
		//create a new directory with timestamp
		Calendar cal = Calendar.getInstance();
    	cal.getTime();
		SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy_HH-mm-ss");
    	String time = sdf.format(cal.getTime());
    	(new File("./"+time)).mkdirs();

		VertexNameProvider<Node> vProvider = new VertexNameProvider<Node>() {	
			@Override
			public String getVertexName(Node arg0) {
				byte[] nodeId = arg0.getNodeId();
				int newInt = 0;
				//only for length of 2 bytes at the moment
				for(int i = 0; i < nodeId.length ; i++){
					newInt += ((nodeId[i]& 0xFF) << ((1-i)*8));
				}
				return newInt+"";
			}
		};
		DOTExporter<Node, MACPacket> ex = new DOTExporter<Node, MACPacket>(vProvider, null, null);
		
		DirectedGraph<Node, MACPacket> testGraph;
		//create a graph for each trace
		for(int i = 0 ; i < numberOfTraces; i++){
			ArrayList<MACPacket> tmpPacketList = graphPacketsLists.get(i);
			testGraph = new DefaultDirectedGraph<Node, MACPacket>(MACPacket.class);
//			for(Node n: nodes){
//				testGraph.addVertex(n);
//			}
			for(MACPacket p : tmpPacketList){
				testGraph.addVertex(p.getSourceNode());
				testGraph.addVertex(p.getDestinationNode());
				testGraph.addEdge(p.getSourceNode(), p.getDestinationNode(), p);
			}
			try {
				FileWriter writer = new FileWriter(new File(time + "/GRAPH"+i+"FL"+tmpPacketList.get(0).getFlowLabel()+".txt"));
				ex.export( writer, testGraph);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		//create a graph for all together at least
		testGraph = new DefaultDirectedGraph<Node, MACPacket>(MACPacket.class);
		for(Node n: nodes){
			testGraph.addVertex(n);
		}
		for(MACPacket p : packets){
			testGraph.addEdge(p.getSourceNode(), p.getDestinationNode(), p);
		}
		try {
			FileWriter writer = new FileWriter(new File(time + "/CompleteGraph.txt"));
			ex.export( writer, testGraph);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public ArrayList<MACPacket> getPackets(){
		return packets;
	}
	
	public ArrayList<Node> getNodes(){
		return nodes;
	}
}
