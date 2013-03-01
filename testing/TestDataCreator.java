package packettracking.testing;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;

import org.jgrapht.DirectedGraph;
import org.jgrapht.ext.DOTExporter;
import org.jgrapht.ext.VertexNameProvider;
import org.jgrapht.graph.DefaultDirectedGraph;

import packettracking.model.MACPacket;
import packettracking.model.MultihopPacketTrace;
import packettracking.model.Node;
import packettracking.utils.Calculator;

/**
 * The TestData Creator is used to test performance of the application in
 * efficiency and effectivity.
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-23        
 */   
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
		
		/*		
		//easy part, create random nodes
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
//		ArrayList<ArrayList<MACPacket>> graphPacketsLists = new ArrayList<ArrayList<MACPacket>>(); 		
		

		//more complex part: create traces
		for(int i = 0; i < numberOfTraces;i++){
			//set up hops
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
//			graphPacketsLists.add(graphPacketList);
		}

		

		
/*
		
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
		} */
	}
	
	/**
	 * Creates nodes, packets and traces for the time evaluation
	 * 
	 * @param numberOfNodes		the number of nodes to be created
	 * @param numberOfTraces	the number of traces to be created
	 * @param hops				the number of hops for each trace
	 */
	public void createTimeTraces(int numberOfTraces, int hops, int timeInterval){
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();
		
		int numberOfNodes = 21;
		
		for(int i = 0; i < numberOfNodes;i++){
			byte[] tmpNodeId = new byte[2];
			for(int j = 0; j < tmpNodeId.length;j++){
				double randomDouble = Math.random()*256.0;
				tmpNodeId[j]= (byte)(int)randomDouble;
			}
			//check for doubled address
			boolean existing = false;
			for(Node n : nodes){
				if(Arrays.equals(n.getNodeId(),tmpNodeId)){
					existing = true;
					i--;
				}
			}
			//add new node to nodelist
			if(!existing){
				Node tmpNode = new Node(tmpNodeId);
				nodes.add(tmpNode);
			}
		}
		
		
		
		//more complex part: create traces
		for(int i = 0; i < numberOfTraces;i++){
			//set up hops
			//a list of nodes left to use in the trace
			ArrayList<Node> nodesLeft = new ArrayList<Node>();
			nodesLeft.addAll(nodes);
			Node actualPosition = nodesLeft.remove((int)(Math.random()*nodesLeft.size()));
			Node firstPosition = new Node(actualPosition.getNodeId());
			Node lastPosition = nodesLeft.remove((int)(Math.random()*nodesLeft.size()));
			int timeCounter = (int)(Math.random()*timeInterval); 
			//generate a flowLabel
			//first the id from the nodeid/address between 0 and 1024
			int flowLabelId = (Calculator.byteArrayToInt(actualPosition.getNodeId())) % 1024;
			//now a counter-number for the label
			int flowLabelCounter = (int)(Math.random()*1024);
			int flowLabel = (flowLabelId << 10) + flowLabelCounter;
			byte[] flowLabelArray = ByteBuffer.allocate(4).putInt(flowLabel).array(); //array with one field to much ... ignore it
			
			//example data with flow label, originator and final destination
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			//now use flowLabel to change the payload at position 2,3 and 4
			payload[2] = flowLabelArray[1];
			payload[3] = flowLabelArray[2];
			payload[4] = flowLabelArray[3];
			
			for(int j = 0; j < hops; j++){
				//get next hop, 
				Node nextPosition;
				//last hop ? jump to destination
				if(j == hops -1){
					nextPosition = lastPosition;
				} 
				//... or it's a new one
				else {
					nextPosition = nodesLeft.remove((int)(Math.random()*nodesLeft.size()));
				}

				//create info for the two packets
				MACPacket p = new MACPacket(true);
				p.setSourceNode(actualPosition);
				p.setDestinationNode(nextPosition);
				p.setPayload(payload);
				
				p.setIPHC(true);
				p.setOriginator(firstPosition.getNodeId());
				p.setFinalDestination(lastPosition.getNodeId());
				
				byte[] seconds = ByteBuffer.allocate(4).putInt(timeCounter).array();
				p.setSeconds(seconds);
				p.setMicroSeconds(new byte[]{0,0,0,0});
				p.setMilliSeconds(new byte[]{0,0,0,0});
				p.setLoggedAt(actualPosition);
				
				//adding packet one (sent packet)
				actualPosition.addSentPackets(p);
				packets.add(p);
				
				//changing time for packet two
				timeCounter += 1; //1 seconds transmission time
				p = new MACPacket(true);
				p.setSourceNode(actualPosition);
				p.setDestinationNode(nextPosition);
				p.setPayload(payload);
				
				p.setIPHC(true);
				p.setOriginator(firstPosition.getNodeId());
				p.setFinalDestination(lastPosition.getNodeId());
				
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
			}
		}
	}
	
	/**
	 * Creates nodes, packets and traces for the quality evaluation
	 * The traces include flow label, originator and final destination
	 * 
	 * @param seconds	the number of seconds as interval all traces start within
	 * @param traces 	the number of traces to be created
	 * @return compareTraces	the created traces for comparison to check correctness of the algorithm
	 */
	public ArrayList<MultihopPacketTrace> createGoodTracesFull(int seconds, int traces){
		ArrayList<MultihopPacketTrace> compareTraces = new ArrayList<MultihopPacketTrace>();
		packets = new ArrayList<MACPacket>();
		nodes = createNodesInOrder(6);
		
		int milliseconds = seconds * 1000;
		
		//one fourth of the traces for each possible flow in random order !
		int routeADCount = traces/4;
		int routeAFCount = traces/4;
		int routeEDCount = traces/4;
		int routeEFCount = traces/4;
		
		int flowLabelCounterA = 0;
		int flowLabelCounterE = 0;
		
		//A equals 2000 (index 0)
		//B equals 2001 ...
		//C equals 2002
		//D equals 2003
		//E equals 2004
		//F equals 2005 (index 5)
		
		for(int i = 0; i < traces;i++){
			//select one of the four routes by random
			Node startingNode = null;
			Node endingNode = null;
			while(startingNode == null){
				int choice = (int) (Math.random()*4);
				if(choice == 0 && routeADCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(3);
					routeADCount--;
					flowLabelCounterA++;
					if(flowLabelCounterA > 1023){
						flowLabelCounterA = 1;
					}
				} else if(choice == 1 && routeAFCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(5);
					routeAFCount--;
					flowLabelCounterA++;
					if(flowLabelCounterA > 1023){
						flowLabelCounterA = 1;
					}
				} else if(choice == 2 && routeEDCount > 0){
					startingNode = nodes.get(4);
					endingNode = nodes.get(3);
					routeEDCount--;
					flowLabelCounterE++;
					if(flowLabelCounterE > 1023){
						flowLabelCounterE = 1;
					}
				} else if(choice == 3 && routeEFCount > 0) {
					startingNode = nodes.get(4);
					endingNode = nodes.get(5);
					routeEFCount--;
					flowLabelCounterE++;
					if(flowLabelCounterE > 1023){
						flowLabelCounterE = 1;
					}
				}
			}
			
			//set the starting time for each trace
			int recentMillis = milliseconds/traces * i;
			int recentSeconds = recentMillis / 1000;
			recentMillis = recentMillis % 1000;
			
			//generate special attributes
			//set flow label
			int flowLabelId = (Calculator.byteArrayToInt(startingNode.getNodeId())) % 1024;
			int flowLabelCounter = 0;
			//now a counter-number for the label, either from A or E
			if(startingNode.equals(nodes.get(0))){
				flowLabelCounter = flowLabelCounterA;
			} else {
				flowLabelCounter = flowLabelCounterE;
			}
			int flowLabel = (flowLabelId << 10) + flowLabelCounter;	
			
			//create a new comparison trace
			MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
			
			//example data ... not important
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			//now use flowLabel to change the payload at position 2,3 and 4
			
			//set all the way by hand, everytime 6 MACPackets
			MACPacket p1 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p1.setPayload(payload);
			
			p1.setSourceNode(startingNode);
			p1.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p1.setIPHC(true);
			p1.setFlowLabel(flowLabel);
			p1.setOriginator(startingNode.getNodeId());
			p1.setFinalDestination(endingNode.getNodeId());
			
			p1.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1.setMicroSeconds(new byte[]{0,0,0,0});
			p1.setLoggedAt(startingNode);
			
			//adding packet one (sent packet)
			startingNode.addSentPackets(p1);
			packets.add(p1);
			tmpTrace.addPacket(p1);
			
			
			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			
			//now second packet
			MACPacket p2 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p2.setPayload(payload);
			
			p2.setSourceNode(startingNode);
			p2.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p2.setIPHC(true);
			p2.setFlowLabel(flowLabel);
			p2.setOriginator(startingNode.getNodeId());
			p2.setFinalDestination(endingNode.getNodeId());
			
			p2.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2.setMicroSeconds(new byte[]{0,0,0,0});
			p2.setLoggedAt(nodes.get(1));
			
			//adding packet two (received packet)
			nodes.get(1).addReceivedPackets(p2);
			packets.add(p2);
			tmpTrace.addPacket(p2);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p3 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p3.setPayload(payload);
					
			p3.setSourceNode(nodes.get(1));
			p3.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p3.setIPHC(true);
			p3.setFlowLabel(flowLabel);
			p3.setOriginator(startingNode.getNodeId());
			p3.setFinalDestination(endingNode.getNodeId());
			
			p3.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3.setMicroSeconds(new byte[]{0,0,0,0});
			p3.setLoggedAt(nodes.get(1));
			
			//adding packet one (sent packet)
			nodes.get(1).addSentPackets(p3);
			packets.add(p3);
			tmpTrace.addPacket(p3);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			//now second packet
			MACPacket p4 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p4.setPayload(payload);
			
			p4.setSourceNode(nodes.get(1));
			p4.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p4.setIPHC(true);
			p4.setFlowLabel(flowLabel);
			p4.setOriginator(startingNode.getNodeId());
			p4.setFinalDestination(endingNode.getNodeId());
			
			p4.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4.setMicroSeconds(new byte[]{0,0,0,0});
			p4.setLoggedAt(nodes.get(2));
			
			//adding packet two (received packet)
			nodes.get(2).addReceivedPackets(p4);
			packets.add(p4);
			tmpTrace.addPacket(p4);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p5 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p5.setPayload(payload);
			
			p5.setSourceNode(nodes.get(2));
			p5.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p5.setIPHC(true);
			p5.setFlowLabel(flowLabel);
			p5.setOriginator(startingNode.getNodeId());
			p5.setFinalDestination(endingNode.getNodeId());
			
			p5.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5.setMicroSeconds(new byte[]{0,0,0,0});
			p5.setLoggedAt(nodes.get(2));
			
			//adding packet one (sent packet)
			nodes.get(2).addSentPackets(p5);
			packets.add(p5);
			tmpTrace.addPacket(p5);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}

			
			
			//now the sixth and last packet
			MACPacket p6 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p6.setPayload(payload);
			
			p6.setSourceNode(nodes.get(2));
			p6.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p6.setIPHC(true);
			p6.setFlowLabel(flowLabel);
			p6.setOriginator(startingNode.getNodeId());
			p6.setFinalDestination(endingNode.getNodeId());
			
			p6.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6.setMicroSeconds(new byte[]{0,0,0,0});
			p6.setLoggedAt(endingNode);
			
			//adding packet two (received packet)
			endingNode.addReceivedPackets(p6);
			packets.add(p6);
			tmpTrace.addPacket(p6);
			
			compareTraces.add(tmpTrace);
		}
		return compareTraces;
	}
	

		
	
	/**
	 * Creates nodes, packets and traces for the quality evaluation
	 * The traces include flow label, originator and final destination and fragmentation
	 * 
	 * @param seconds	the number of seconds as interval all traces start within
	 * @param traces 	the number of traces to be created
	 * @return compareTraces	the created traces for comparison to check correctness of the algorithm
	 */
	public ArrayList<MultihopPacketTrace> createGoodTracesFullFrag(int seconds, int traces){
		ArrayList<MultihopPacketTrace> compareTraces = new ArrayList<MultihopPacketTrace>();
		packets = new ArrayList<MACPacket>();
		nodes = createNodesInOrder(6);
		
		int milliseconds = seconds * 1000;
		
		//one fourth of the traces for each possible flow in random order !
		int routeADCount = traces/4;
		int routeAFCount = traces/4;
		int routeEDCount = traces/4;
		int routeEFCount = traces/4;
		
		int flowLabelCounterA = 0;
		int flowLabelCounterE = 0;
		
		//A equals 2000 (index 0)
		//B equals 2001 ...
		//C equals 2002
		//D equals 2003
		//E equals 2004
		//F equals 2005 (index 5)
		
		int fragmentationTagCounterA = -1;
		int fragmentationTagCounterB = 0;
		int fragmentationTagCounterC = 0;
		int fragmentationTagCounterE = -1;
		
		for(int i = 0; i < traces;i++){
			//select one of the four routes by random
			Node startingNode = null;
			Node endingNode = null;
			while(startingNode == null){
				int choice = (int) (Math.random()*4);
				if(choice == 0 && routeADCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(3);
					routeADCount--;
					flowLabelCounterA++;
					if(flowLabelCounterA > 1023){
						flowLabelCounterA = 1;
					}
					fragmentationTagCounterA = (fragmentationTagCounterA + 1) % 256;
				} else if(choice == 1 && routeAFCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(5);
					routeAFCount--;
					flowLabelCounterA++;
					if(flowLabelCounterA > 1023){
						flowLabelCounterA = 1;
					}
					fragmentationTagCounterA = (fragmentationTagCounterA + 1) % 256;
				} else if(choice == 2 && routeEDCount > 0){
					startingNode = nodes.get(4);
					endingNode = nodes.get(3);
					routeEDCount--;
					flowLabelCounterE++;
					if(flowLabelCounterE > 1023){
						flowLabelCounterE = 1;
					}
					fragmentationTagCounterE = (fragmentationTagCounterE + 1) % 256;
				} else if(choice == 3 && routeEFCount > 0) {
					startingNode = nodes.get(4);
					endingNode = nodes.get(5);
					routeEFCount--;
					flowLabelCounterE++;
					if(flowLabelCounterE > 1023){
						flowLabelCounterE = 1;
					}
					fragmentationTagCounterE = (fragmentationTagCounterE + 1) % 256;
				}
			}
			
			//set the starting time for each trace
			int recentMillis = milliseconds/traces * i;
			int recentSeconds = recentMillis / 1000;
			recentMillis = recentMillis % 1000;
			
			//generate special attributes
			//set flow label
			int flowLabelId = (Calculator.byteArrayToInt(startingNode.getNodeId())) % 1024;
			int flowLabelCounter = 0;
			//now a counter-number for the label, either from A or E
			if(startingNode.equals(nodes.get(0))){
				flowLabelCounter = flowLabelCounterA;
			} else {
				flowLabelCounter = flowLabelCounterE;
			}
			int flowLabel = (flowLabelId << 10) + flowLabelCounter;	
			
			//create a new comparison trace
			MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
			
			//example data ... not important, it gets overwritten to be sure of exact content
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			byte[] fragpayload = new byte[]{107,59,0,0,1,58,2,5,4,3,2};
			//now use flowLabel to change the payload at position 2,3 and 4
			
			//set all the way by hand, everytime 6 MACPackets + 6 fragmentation packets
			MACPacket p1 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p1.setPayload(payload);
			
			p1.setSourceNode(startingNode);
			p1.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node and fragmentation
			p1.setIPHC(true);
			p1.setFlowLabel(flowLabel);
			p1.setOriginator(startingNode.getNodeId());
			p1.setFinalDestination(endingNode.getNodeId());
			p1.setFragmentationFirstHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p1.setDatagramTag(fragmentationTagCounterA);
			} else {
				p1.setDatagramTag(fragmentationTagCounterE);
			}
			p1.setDatagramSize(20);
			
			p1.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1.setMicroSeconds(new byte[]{0,0,0,0});
			p1.setLoggedAt(startingNode);
			
			MACPacket p1frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p1frag.setPayload(fragpayload);
			
			p1frag.setSourceNode(startingNode);
			p1frag.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p1frag.setIPHC(false);
			p1frag.setFragmentationSubsequentHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p1frag.setDatagramTag(fragmentationTagCounterA);
			} else {
				p1frag.setDatagramTag(fragmentationTagCounterE);
			}
			p1frag.setDatagramSize(20);
			
			p1frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1frag.setMicroSeconds(new byte[]{0,0,0,0});
			p1frag.setLoggedAt(startingNode);
			
			//adding packet one (sent packet)
			startingNode.addSentPackets(p1);
			packets.add(p1);
			tmpTrace.addPacket(p1);
			//adding packet one fragmentation (sent packet)
			startingNode.addSentPackets(p1frag);
			packets.add(p1frag);
			tmpTrace.addPacket(p1frag);
			
			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			
			//now second packet
			MACPacket p2 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p2.setPayload(payload);
			
			p2.setSourceNode(startingNode);
			p2.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p2.setIPHC(true);
			p2.setFlowLabel(flowLabel);
			p2.setOriginator(startingNode.getNodeId());
			p2.setFinalDestination(endingNode.getNodeId());
			p2.setFragmentationFirstHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p2.setDatagramTag(fragmentationTagCounterA);
			} else {
				p2.setDatagramTag(fragmentationTagCounterE);
			}
			p2.setDatagramSize(20);
			
			p2.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2.setMicroSeconds(new byte[]{0,0,0,0});
			p2.setLoggedAt(nodes.get(1));
			
			MACPacket p2frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p2frag.setPayload(fragpayload);
			
			p2frag.setSourceNode(startingNode);
			p2frag.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p2frag.setIPHC(false);
			p2frag.setFragmentationSubsequentHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p2frag.setDatagramTag(fragmentationTagCounterA);
			} else {
				p2frag.setDatagramTag(fragmentationTagCounterE);
			}
			p2frag.setDatagramSize(20);
			
			p2frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2frag.setMicroSeconds(new byte[]{0,0,0,0});
			p2frag.setLoggedAt(nodes.get(1));
			
			//adding packet two (received packet)
			nodes.get(1).addReceivedPackets(p2);
			packets.add(p2);
			tmpTrace.addPacket(p2);
			
			//adding packet two fragmentation (received packet)
			nodes.get(1).addReceivedPackets(p2frag);
			packets.add(p2frag);
			tmpTrace.addPacket(p2frag);
			
			//packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p3 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p3.setPayload(payload);
					
			p3.setSourceNode(nodes.get(1));
			p3.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p3.setIPHC(true);
			p3.setFlowLabel(flowLabel);
			p3.setOriginator(startingNode.getNodeId());
			p3.setFinalDestination(endingNode.getNodeId());
			p3.setFragmentationFirstHeader(true);
			p3.setDatagramTag(fragmentationTagCounterB);
			p3.setDatagramSize(20);
			
			p3.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3.setMicroSeconds(new byte[]{0,0,0,0});
			p3.setLoggedAt(nodes.get(1));
			
			MACPacket p3frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p3frag.setPayload(fragpayload);
			
			p3frag.setSourceNode(nodes.get(1));
			p3frag.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p3frag.setIPHC(false);
			p3frag.setFragmentationSubsequentHeader(true);
			p3frag.setDatagramTag(fragmentationTagCounterB);
			p3frag.setDatagramSize(20);
			
			p3frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3frag.setMicroSeconds(new byte[]{0,0,0,0});
			p3frag.setLoggedAt(nodes.get(1));
			
			//adding packet three (sent packet)
			nodes.get(1).addSentPackets(p3);
			packets.add(p3);
			tmpTrace.addPacket(p3);
			
			//adding packet three fragmentation (sent packet)
			nodes.get(1).addSentPackets(p3frag);
			packets.add(p3frag);
			tmpTrace.addPacket(p3frag);

			
			
			//packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			//now second packet
			MACPacket p4 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p4.setPayload(payload);
			
			p4.setSourceNode(nodes.get(1));
			p4.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p4.setIPHC(true);
			p4.setFlowLabel(flowLabel);
			p4.setOriginator(startingNode.getNodeId());
			p4.setFinalDestination(endingNode.getNodeId());
			p4.setFragmentationFirstHeader(true);
			p4.setDatagramTag(fragmentationTagCounterB);
			p4.setDatagramSize(20);
			
			p4.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4.setMicroSeconds(new byte[]{0,0,0,0});
			p4.setLoggedAt(nodes.get(2));
			
			MACPacket p4frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p4frag.setPayload(fragpayload);
			
			p4frag.setSourceNode(nodes.get(1));
			p4frag.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p4frag.setIPHC(false);
			p4frag.setFragmentationSubsequentHeader(true);
			p4frag.setDatagramTag(fragmentationTagCounterB);
			p4frag.setDatagramSize(20);
			
			p4frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4frag.setMicroSeconds(new byte[]{0,0,0,0});
			p4frag.setLoggedAt(nodes.get(2));
			
			//adding packet four (received packet)
			nodes.get(2).addReceivedPackets(p4);
			packets.add(p4);
			tmpTrace.addPacket(p4);
			
			//adding packet four fragmentation (received packet)
			nodes.get(2).addReceivedPackets(p4frag);
			packets.add(p4frag);
			tmpTrace.addPacket(p4frag);
			
			//increase counter for individual tags
			fragmentationTagCounterB++;
			
			//packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p5 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p5.setPayload(payload);
			
			p5.setSourceNode(nodes.get(2));
			p5.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p5.setIPHC(true);
			p5.setFlowLabel(flowLabel);
			p5.setOriginator(startingNode.getNodeId());
			p5.setFinalDestination(endingNode.getNodeId());
			p5.setFragmentationFirstHeader(true);
			p5.setDatagramTag(fragmentationTagCounterC);
			p5.setDatagramSize(20);
			
			p5.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5.setMicroSeconds(new byte[]{0,0,0,0});
			p5.setLoggedAt(nodes.get(2));
			
			MACPacket p5frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p5frag.setPayload(fragpayload);
			
			p5frag.setSourceNode(nodes.get(2));
			p5frag.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p5frag.setIPHC(false);
			p5frag.setFragmentationSubsequentHeader(true);
			p5frag.setDatagramTag(fragmentationTagCounterC);
			p5frag.setDatagramSize(20);
			
			p5frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5frag.setMicroSeconds(new byte[]{0,0,0,0});
			p5frag.setLoggedAt(nodes.get(2));
			
			//adding packet five (sent packet)
			nodes.get(2).addSentPackets(p5);
			packets.add(p5);
			tmpTrace.addPacket(p5);

			//adding packet five fragmentation (sent packet)
			nodes.get(2).addSentPackets(p5frag);
			packets.add(p5frag);
			tmpTrace.addPacket(p5frag);
			
			
			//packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}

			
			
			//now the sixth and last packet
			MACPacket p6 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p6.setPayload(payload);
			
			p6.setSourceNode(nodes.get(2));
			p6.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p6.setIPHC(true);
			p6.setFlowLabel(flowLabel);
			p6.setOriginator(startingNode.getNodeId());
			p6.setFinalDestination(endingNode.getNodeId());
			p6.setFragmentationFirstHeader(true);
			p6.setDatagramTag(fragmentationTagCounterC);
			p6.setDatagramSize(20);
			
			p6.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6.setMicroSeconds(new byte[]{0,0,0,0});
			p6.setLoggedAt(endingNode);
			
			MACPacket p6frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p6frag.setPayload(fragpayload);
			
			p6frag.setSourceNode(nodes.get(2));
			p6frag.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p6frag.setIPHC(false);
			p6frag.setFragmentationSubsequentHeader(true);
			p6frag.setDatagramTag(fragmentationTagCounterC);
			p6frag.setDatagramSize(20);
			
			p6frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6frag.setMicroSeconds(new byte[]{0,0,0,0});
			p6frag.setLoggedAt(endingNode);
			
			//adding packet six (received packet)
			endingNode.addReceivedPackets(p6);
			packets.add(p6);
			tmpTrace.addPacket(p6);
			
			//adding packet six fragmentation (received packet)
			endingNode.addReceivedPackets(p6frag);
			packets.add(p6frag);
			tmpTrace.addPacket(p6frag);
			
			//increase counter for individual tags
			fragmentationTagCounterC++;
			
			compareTraces.add(tmpTrace);
		}
		return compareTraces;
	}
	
	/**
	 * Creates nodes, packets and traces for the quality evaluation
	 * The traces include flow label
	 * 
	 * @param seconds	the number of seconds as interval all traces start within
	 * @param traces 	the number of traces to be created
	 * @return compareTraces	the created traces for comparison to check correctness of the algorithm
	 */
	public ArrayList<MultihopPacketTrace> createGoodTracesFlow(int seconds, int traces){
		ArrayList<MultihopPacketTrace> compareTraces = new ArrayList<MultihopPacketTrace>();
		packets = new ArrayList<MACPacket>();
		nodes = createNodesInOrder(6);
		
		int milliseconds = seconds * 1000;
		
		//one fourth of the traces for each possible flow in random order !
		int routeADCount = traces/4;
		int routeAFCount = traces/4;
		int routeEDCount = traces/4;
		int routeEFCount = traces/4;
		
		int flowLabelCounterA = -1;
		int flowLabelCounterE = -1;
		
		//A equals 2000 (index 0)
		//B equals 2001 ...
		//C equals 2002
		//D equals 2003
		//E equals 2004
		//F equals 2005 (index 5)
		
		for(int i = 0; i < traces;i++){
			//select one of the four routes by random
			Node startingNode = null;
			Node endingNode = null;
			while(startingNode == null){
				int choice = (int) (Math.random()*4);
				if(choice == 0 && routeADCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(3);
					routeADCount--;
					flowLabelCounterA++;
					if(flowLabelCounterA > 1023){
						flowLabelCounterA = 1;
					}
				} else if(choice == 1 && routeAFCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(5);
					routeAFCount--;
					flowLabelCounterA++;
					if(flowLabelCounterA > 1023){
						flowLabelCounterA = 1;
					}
				} else if(choice == 2 && routeEDCount > 0){
					startingNode = nodes.get(4);
					endingNode = nodes.get(3);
					routeEDCount--;
					flowLabelCounterE++;
					if(flowLabelCounterE > 1023){
						flowLabelCounterE = 1;
					}
				} else if(choice == 3 && routeEFCount > 0) {
					startingNode = nodes.get(4);
					endingNode = nodes.get(5);
					routeEFCount--;
					flowLabelCounterE++;
					if(flowLabelCounterE > 1023){
						flowLabelCounterE = 1;
					}
				}
			}
			
			//set the starting time for each trace
			int recentMillis = milliseconds/traces * i;
			int recentSeconds = recentMillis / 1000;
			recentMillis = recentMillis % 1000;
			
			//generate special attributes
			//set flow label
			int flowLabelId = (Calculator.byteArrayToInt(startingNode.getNodeId())) % 1024;
			int flowLabelCounter = 0;
			//now a counter-number for the label, either from A or E
			if(startingNode.equals(nodes.get(0))){
				flowLabelCounter = flowLabelCounterA;
			} else {
				flowLabelCounter = flowLabelCounterE;
			}
			int flowLabel = (flowLabelId << 10) + flowLabelCounter;	
			
			//create a new comparison trace
			MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
			
			//example data ... not important
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			//now use flowLabel to change the payload at position 2,3 and 4
			
			//set all the way by hand, everytime 6 MACPackets
			MACPacket p1 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p1.setPayload(payload);
			
			p1.setSourceNode(startingNode);
			p1.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p1.setIPHC(true);
			p1.setFlowLabel(flowLabel);
			p1.setOriginator(null);
			p1.setFinalDestination(null);
			
			p1.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1.setMicroSeconds(new byte[]{0,0,0,0});
			p1.setLoggedAt(startingNode);
			
			//adding packet one (sent packet)
			startingNode.addSentPackets(p1);
			packets.add(p1);
			tmpTrace.addPacket(p1);
			
			
			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			
			//now second packet
			MACPacket p2 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p2.setPayload(payload);
			
			p2.setSourceNode(startingNode);
			p2.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p2.setIPHC(true);
			p2.setFlowLabel(flowLabel);
			p2.setOriginator(null);
			p2.setFinalDestination(null);
			
			p2.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2.setMicroSeconds(new byte[]{0,0,0,0});
			p2.setLoggedAt(nodes.get(1));
			
			//adding packet two (received packet)
			nodes.get(1).addReceivedPackets(p2);
			packets.add(p2);
			tmpTrace.addPacket(p2);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p3 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p3.setPayload(payload);
					
			p3.setSourceNode(nodes.get(1));
			p3.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p3.setIPHC(true);
			p3.setFlowLabel(flowLabel);
			p3.setOriginator(null);
			p3.setFinalDestination(null);
			
			p3.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3.setMicroSeconds(new byte[]{0,0,0,0});
			p3.setLoggedAt(nodes.get(1));
			
			//adding packet one (sent packet)
			nodes.get(1).addSentPackets(p3);
			packets.add(p3);
			tmpTrace.addPacket(p3);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			//now second packet
			MACPacket p4 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p4.setPayload(payload);
			
			p4.setSourceNode(nodes.get(1));
			p4.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p4.setIPHC(true);
			p4.setFlowLabel(flowLabel);
			p4.setOriginator(null);
			p4.setFinalDestination(null);
			
			p4.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4.setMicroSeconds(new byte[]{0,0,0,0});
			p4.setLoggedAt(nodes.get(2));
			
			//adding packet two (received packet)
			nodes.get(2).addReceivedPackets(p4);
			packets.add(p4);
			tmpTrace.addPacket(p4);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p5 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p5.setPayload(payload);
			
			p5.setSourceNode(nodes.get(2));
			p5.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p5.setIPHC(true);
			p5.setFlowLabel(flowLabel);
			p5.setOriginator(null);
			p5.setFinalDestination(null);
			
			p5.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5.setMicroSeconds(new byte[]{0,0,0,0});
			p5.setLoggedAt(nodes.get(2));
			
			//adding packet one (sent packet)
			nodes.get(2).addSentPackets(p5);
			packets.add(p5);
			tmpTrace.addPacket(p5);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}

			
			
			//now the sixth and last packet
			MACPacket p6 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p6.setPayload(payload);
			
			p6.setSourceNode(nodes.get(2));
			p6.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p6.setIPHC(true);
			p6.setFlowLabel(flowLabel);
			p6.setOriginator(null);
			p6.setFinalDestination(null);
			
			p6.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6.setMicroSeconds(new byte[]{0,0,0,0});
			p6.setLoggedAt(endingNode);
			
			//adding packet two (received packet)
			endingNode.addReceivedPackets(p6);
			packets.add(p6);
			tmpTrace.addPacket(p6);
			
			compareTraces.add(tmpTrace);
		}
		return compareTraces;
	}
	
	/**
	 * Creates nodes, packets and traces for the quality evaluation
	 * The traces include originator and final destination
	 * 
	 * @param seconds	the number of seconds as interval all traces start within
	 * @param traces 	the number of traces to be created
	 * @return compareTraces	the created traces for comparison to check correctness of the algorithm
	 */
	public ArrayList<MultihopPacketTrace> createGoodTracesStartEndFrag(int seconds, int traces){
		ArrayList<MultihopPacketTrace> compareTraces = new ArrayList<MultihopPacketTrace>();
		packets = new ArrayList<MACPacket>();
		nodes = createNodesInOrder(6);
		
		int milliseconds = seconds * 1000;
		
		//one fourth of the traces for each possible flow in random order !
		int routeADCount = traces/4;
		int routeAFCount = traces/4;
		int routeEDCount = traces/4;
		int routeEFCount = traces/4;
		
		//A equals 2000 (index 0)
		//B equals 2001 ...
		//C equals 2002
		//D equals 2003
		//E equals 2004
		//F equals 2005 (index 5)
		
		int fragmentationTagCounterA = -1;
		int fragmentationTagCounterB = 0;
		int fragmentationTagCounterC = 0;
		int fragmentationTagCounterE = -1;
		
		for(int i = 0; i < traces;i++){
			//select one of the four routes by random
			Node startingNode = null;
			Node endingNode = null;
			while(startingNode == null){
				int choice = (int) (Math.random()*4);
				if(choice == 0 && routeADCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(3);
					routeADCount--;
					fragmentationTagCounterA = (fragmentationTagCounterA + 1) % 256;
				} else if(choice == 1 && routeAFCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(5);
					routeAFCount--;
					fragmentationTagCounterA = (fragmentationTagCounterA + 1) % 256;
				} else if(choice == 2 && routeEDCount > 0){
					startingNode = nodes.get(4);
					endingNode = nodes.get(3);
					routeEDCount--;
					fragmentationTagCounterE = (fragmentationTagCounterE + 1) % 256;
				} else if(choice == 3 && routeEFCount > 0) {
					startingNode = nodes.get(4);
					endingNode = nodes.get(5);
					routeEFCount--;
					fragmentationTagCounterE = (fragmentationTagCounterE + 1) % 256;
				}
			}
			
			//set the starting time for each trace
			int recentMillis = milliseconds/traces * i;
			int recentSeconds = recentMillis / 1000;
			recentMillis = recentMillis % 1000;
			
			//create a new comparison trace
			MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
			
			//example data ... not important, it gets overwritten to be sure of exact content
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			byte[] fragpayload = new byte[]{107,59,0,0,1,58,2,5,4,3,2};
			//now use flowLabel to change the payload at position 2,3 and 4
			
			//set all the way by hand, everytime 6 MACPackets + 6 fragmentation packets
			MACPacket p1 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p1.setPayload(payload);
			
			p1.setSourceNode(startingNode);
			p1.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node and fragmentation
			p1.setIPHC(true);
			p1.setFlowLabel(-1);
			p1.setOriginator(startingNode.getNodeId());
			p1.setFinalDestination(endingNode.getNodeId());
			p1.setFragmentationFirstHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p1.setDatagramTag(fragmentationTagCounterA);
			} else {
				p1.setDatagramTag(fragmentationTagCounterE);
			}
			p1.setDatagramSize(20);
			
			p1.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1.setMicroSeconds(new byte[]{0,0,0,0});
			p1.setLoggedAt(startingNode);
			
			MACPacket p1frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p1frag.setPayload(fragpayload);
			
			p1frag.setSourceNode(startingNode);
			p1frag.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p1frag.setIPHC(false);
			p1frag.setFragmentationSubsequentHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p1frag.setDatagramTag(fragmentationTagCounterA);
			} else {
				p1frag.setDatagramTag(fragmentationTagCounterE);
			}
			p1frag.setDatagramSize(20);
			
			p1frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1frag.setMicroSeconds(new byte[]{0,0,0,0});
			p1frag.setLoggedAt(startingNode);
			
			//adding packet one (sent packet)
			startingNode.addSentPackets(p1);
			packets.add(p1);
			tmpTrace.addPacket(p1);
			//adding packet one fragmentation (sent packet)
			startingNode.addSentPackets(p1frag);
			packets.add(p1frag);
			tmpTrace.addPacket(p1frag);
			
			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			
			//now second packet
			MACPacket p2 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p2.setPayload(payload);
			
			p2.setSourceNode(startingNode);
			p2.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p2.setIPHC(true);
			p2.setFlowLabel(-1);
			p2.setOriginator(startingNode.getNodeId());
			p2.setFinalDestination(endingNode.getNodeId());
			p2.setFragmentationFirstHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p2.setDatagramTag(fragmentationTagCounterA);
			} else {
				p2.setDatagramTag(fragmentationTagCounterE);
			}
			p2.setDatagramSize(20);
			
			p2.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2.setMicroSeconds(new byte[]{0,0,0,0});
			p2.setLoggedAt(nodes.get(1));
			
			MACPacket p2frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p2frag.setPayload(fragpayload);
			
			p2frag.setSourceNode(startingNode);
			p2frag.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p2frag.setIPHC(false);
			p2frag.setFragmentationSubsequentHeader(true);
			if(startingNode.equals(nodes.get(0))){
				p2frag.setDatagramTag(fragmentationTagCounterA);
			} else {
				p2frag.setDatagramTag(fragmentationTagCounterE);
			}
			p2frag.setDatagramSize(20);
			
			p2frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2frag.setMicroSeconds(new byte[]{0,0,0,0});
			p2frag.setLoggedAt(nodes.get(1));
			
			//adding packet two (received packet)
			nodes.get(1).addReceivedPackets(p2);
			packets.add(p2);
			tmpTrace.addPacket(p2);
			
			//adding packet two fragmentation (received packet)
			nodes.get(1).addReceivedPackets(p2frag);
			packets.add(p2frag);
			tmpTrace.addPacket(p2frag);
			
			//packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p3 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p3.setPayload(payload);
					
			p3.setSourceNode(nodes.get(1));
			p3.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p3.setIPHC(true);
			p3.setFlowLabel(-1);
			p3.setOriginator(startingNode.getNodeId());
			p3.setFinalDestination(endingNode.getNodeId());
			p3.setFragmentationFirstHeader(true);
			p3.setDatagramTag(fragmentationTagCounterB);
			p3.setDatagramSize(20);
			
			p3.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3.setMicroSeconds(new byte[]{0,0,0,0});
			p3.setLoggedAt(nodes.get(1));
			
			MACPacket p3frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p3frag.setPayload(fragpayload);
			
			p3frag.setSourceNode(nodes.get(1));
			p3frag.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p3frag.setIPHC(false);
			p3frag.setFragmentationSubsequentHeader(true);
			p3frag.setDatagramTag(fragmentationTagCounterB);
			p3frag.setDatagramSize(20);
			
			p3frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3frag.setMicroSeconds(new byte[]{0,0,0,0});
			p3frag.setLoggedAt(nodes.get(1));
			
			//adding packet three (sent packet)
			nodes.get(1).addSentPackets(p3);
			packets.add(p3);
			tmpTrace.addPacket(p3);
			
			//adding packet three fragmentation (sent packet)
			nodes.get(1).addSentPackets(p3frag);
			packets.add(p3frag);
			tmpTrace.addPacket(p3frag);

			
			
			//packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			//now second packet
			MACPacket p4 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p4.setPayload(payload);
			
			p4.setSourceNode(nodes.get(1));
			p4.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p4.setIPHC(true);
			p4.setFlowLabel(-1);
			p4.setOriginator(startingNode.getNodeId());
			p4.setFinalDestination(endingNode.getNodeId());
			p4.setFragmentationFirstHeader(true);
			p4.setDatagramTag(fragmentationTagCounterB);
			p4.setDatagramSize(20);
			
			p4.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4.setMicroSeconds(new byte[]{0,0,0,0});
			p4.setLoggedAt(nodes.get(2));
			
			MACPacket p4frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p4frag.setPayload(fragpayload);
			
			p4frag.setSourceNode(nodes.get(1));
			p4frag.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p4frag.setIPHC(false);
			p4frag.setFragmentationSubsequentHeader(true);
			p4frag.setDatagramTag(fragmentationTagCounterB);
			p4frag.setDatagramSize(20);
			
			p4frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4frag.setMicroSeconds(new byte[]{0,0,0,0});
			p4frag.setLoggedAt(nodes.get(2));
			
			//adding packet four (received packet)
			nodes.get(2).addReceivedPackets(p4);
			packets.add(p4);
			tmpTrace.addPacket(p4);
			
			//adding packet four fragmentation (received packet)
			nodes.get(2).addReceivedPackets(p4frag);
			packets.add(p4frag);
			tmpTrace.addPacket(p4frag);
			
			//increase counter for individual tags
			fragmentationTagCounterB++;
			
			//packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p5 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p5.setPayload(payload);
			
			p5.setSourceNode(nodes.get(2));
			p5.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p5.setIPHC(true);
			p5.setFlowLabel(-1);
			p5.setOriginator(startingNode.getNodeId());
			p5.setFinalDestination(endingNode.getNodeId());
			p5.setFragmentationFirstHeader(true);
			p5.setDatagramTag(fragmentationTagCounterC);
			p5.setDatagramSize(20);
			
			p5.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5.setMicroSeconds(new byte[]{0,0,0,0});
			p5.setLoggedAt(nodes.get(2));
			
			MACPacket p5frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p5frag.setPayload(fragpayload);
			
			p5frag.setSourceNode(nodes.get(2));
			p5frag.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p5frag.setIPHC(false);
			p5frag.setFragmentationSubsequentHeader(true);
			p5frag.setDatagramTag(fragmentationTagCounterC);
			p5frag.setDatagramSize(20);
			
			p5frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5frag.setMicroSeconds(new byte[]{0,0,0,0});
			p5frag.setLoggedAt(nodes.get(2));
			
			//adding packet five (sent packet)
			nodes.get(2).addSentPackets(p5);
			packets.add(p5);
			tmpTrace.addPacket(p5);

			//adding packet five fragmentation (sent packet)
			nodes.get(2).addSentPackets(p5frag);
			packets.add(p5frag);
			tmpTrace.addPacket(p5frag);
			
			
			//packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}

			
			
			//now the sixth and last packet
			MACPacket p6 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p6.setPayload(payload);
			
			p6.setSourceNode(nodes.get(2));
			p6.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p6.setIPHC(true);
			p6.setFlowLabel(-1);
			p6.setOriginator(startingNode.getNodeId());
			p6.setFinalDestination(endingNode.getNodeId());
			p6.setFragmentationFirstHeader(true);
			p6.setDatagramTag(fragmentationTagCounterC);
			p6.setDatagramSize(20);
			
			p6.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6.setMicroSeconds(new byte[]{0,0,0,0});
			p6.setLoggedAt(endingNode);
			
			MACPacket p6frag = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p6frag.setPayload(fragpayload);
			
			p6frag.setSourceNode(nodes.get(2));
			p6frag.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p6frag.setIPHC(false);
			p6frag.setFragmentationSubsequentHeader(true);
			p6frag.setDatagramTag(fragmentationTagCounterC);
			p6frag.setDatagramSize(20);
			
			p6frag.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6frag.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6frag.setMicroSeconds(new byte[]{0,0,0,0});
			p6frag.setLoggedAt(endingNode);
			
			//adding packet six (received packet)
			endingNode.addReceivedPackets(p6);
			packets.add(p6);
			tmpTrace.addPacket(p6);
			
			//adding packet six fragmentation (received packet)
			endingNode.addReceivedPackets(p6frag);
			packets.add(p6frag);
			tmpTrace.addPacket(p6frag);
			
			//increase counter for individual tags
			fragmentationTagCounterC++;
			
			compareTraces.add(tmpTrace);
		}
		return compareTraces;
	}
	
	/**
	 * Creates nodes, packets and traces for the quality evaluation
	 * The traces include originator, final destination and fragmentation
	 * 
	 * @param seconds	the number of seconds as interval all traces start within
	 * @param traces 	the number of traces to be created
	 * @return compareTraces	the created traces for comparison to check correctness of the algorithm
	 */
	public ArrayList<MultihopPacketTrace> createGoodTracesStartEnd(int seconds, int traces){
		ArrayList<MultihopPacketTrace> compareTraces = new ArrayList<MultihopPacketTrace>();
		packets = new ArrayList<MACPacket>();
		nodes = createNodesInOrder(6);
		
		int milliseconds = seconds * 1000;
		
		//one fourth of the traces for each possible flow in random order !
		int routeADCount = traces/4;
		int routeAFCount = traces/4;
		int routeEDCount = traces/4;
		int routeEFCount = traces/4;
		
		//A equals 2000 (index 0)
		//B equals 2001 ...
		//C equals 2002
		//D equals 2003
		//E equals 2004
		//F equals 2005 (index 5)
		
		for(int i = 0; i < traces;i++){
			//select one of the four routes by random
			Node startingNode = null;
			Node endingNode = null;
			while(startingNode == null){
				int choice = (int) (Math.random()*4);
				if(choice == 0 && routeADCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(3);
					routeADCount--;
				} else if(choice == 1 && routeAFCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(5);
					routeAFCount--;
				} else if(choice == 2 && routeEDCount > 0){
					startingNode = nodes.get(4);
					endingNode = nodes.get(3);
					routeEDCount--;
				} else if(choice == 3 && routeEFCount > 0) {
					startingNode = nodes.get(4);
					endingNode = nodes.get(5);
					routeEFCount--;
				}
			}
			
			//set the starting time for each trace
			int recentMillis = milliseconds/traces * i;
			int recentSeconds = recentMillis / 1000;
			recentMillis = recentMillis % 1000;
			
			//generate special attributes
			
			//create a new comparison trace
			MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
			
			//example data ... not important
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			//now use flowLabel to change the payload at position 2,3 and 4
			
			//set all the way by hand, everytime 6 MACPackets
			MACPacket p1 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p1.setPayload(payload);
			
			p1.setSourceNode(startingNode);
			p1.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p1.setIPHC(true);
			p1.setFlowLabel(-1); //equals no flow label
			p1.setOriginator(startingNode.getNodeId());
			p1.setFinalDestination(endingNode.getNodeId());
			
			p1.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1.setMicroSeconds(new byte[]{0,0,0,0});
			p1.setLoggedAt(startingNode);
			
			//adding packet one (sent packet)
			startingNode.addSentPackets(p1);
			packets.add(p1);
			tmpTrace.addPacket(p1);
			
			
			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			
			//now second packet
			MACPacket p2 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p2.setPayload(payload);
			
			p2.setSourceNode(startingNode);
			p2.setDestinationNode(nodes.get(1));
			
			//set iphc flow label and starting- and ending node
			p2.setIPHC(true);
			p2.setFlowLabel(-1); //equals no flow label
			p2.setOriginator(startingNode.getNodeId());
			p2.setFinalDestination(endingNode.getNodeId());
			
			p2.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2.setMicroSeconds(new byte[]{0,0,0,0});
			p2.setLoggedAt(nodes.get(1));
			
			//adding packet two (received packet)
			nodes.get(1).addReceivedPackets(p2);
			packets.add(p2);
			tmpTrace.addPacket(p2);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p3 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p3.setPayload(payload);
					
			p3.setSourceNode(nodes.get(1));
			p3.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p3.setIPHC(true);
			p3.setFlowLabel(-1); //equals no flow label
			p3.setOriginator(startingNode.getNodeId());
			p3.setFinalDestination(endingNode.getNodeId());
			
			p3.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3.setMicroSeconds(new byte[]{0,0,0,0});
			p3.setLoggedAt(nodes.get(1));
			
			//adding packet one (sent packet)
			nodes.get(1).addSentPackets(p3);
			packets.add(p3);
			tmpTrace.addPacket(p3);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			//now second packet
			MACPacket p4 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p4.setPayload(payload);
			
			p4.setSourceNode(nodes.get(1));
			p4.setDestinationNode(nodes.get(2));
			
			//set iphc flow label and starting- and ending node
			p4.setIPHC(true);
			p4.setFlowLabel(-1); //equals no flow label
			p4.setOriginator(startingNode.getNodeId());
			p4.setFinalDestination(endingNode.getNodeId());
			
			p4.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4.setMicroSeconds(new byte[]{0,0,0,0});
			p4.setLoggedAt(nodes.get(2));
			
			//adding packet two (received packet)
			nodes.get(2).addReceivedPackets(p4);
			packets.add(p4);
			tmpTrace.addPacket(p4);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p5 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p5.setPayload(payload);
			
			p5.setSourceNode(nodes.get(2));
			p5.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p5.setIPHC(true);
			p5.setFlowLabel(-1); //equals no flow label
			p5.setOriginator(startingNode.getNodeId());
			p5.setFinalDestination(endingNode.getNodeId());
			
			p5.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5.setMicroSeconds(new byte[]{0,0,0,0});
			p5.setLoggedAt(nodes.get(2));
			
			//adding packet one (sent packet)
			nodes.get(2).addSentPackets(p5);
			packets.add(p5);
			tmpTrace.addPacket(p5);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}

			
			
			//now the sixth and last packet
			MACPacket p6 = new MACPacket(true);
			//payload must be set first, because it gets overwritten by other attributes
			p6.setPayload(payload);
			

			
			p6.setSourceNode(nodes.get(2));
			p6.setDestinationNode(endingNode);
			
			//set iphc flow label and starting- and ending node
			p6.setIPHC(true);
			p6.setFlowLabel(-1); //equals no flow label
			p6.setOriginator(startingNode.getNodeId());
			p6.setFinalDestination(endingNode.getNodeId());
			
			p6.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6.setMicroSeconds(new byte[]{0,0,0,0});
			p6.setLoggedAt(endingNode);
			
			//adding packet two (received packet)
			endingNode.addReceivedPackets(p6);
			packets.add(p6);
			tmpTrace.addPacket(p6);
			
			compareTraces.add(tmpTrace);
		}
		
		return compareTraces;
	}
	
	/**
	 * Creates nodes, packets and traces for the quality evaluation
	 * The traces include nothing but mac header
	 * 
	 * @param seconds	the number of seconds as interval all traces start within
	 * @param traces 	the number of traces to be created
	 * @return compareTraces	the created traces for comparison to check correctness of the algorithm
	 */
	public ArrayList<MultihopPacketTrace> createGoodTracesNothing(int seconds, int traces){
		ArrayList<MultihopPacketTrace> compareTraces = new ArrayList<MultihopPacketTrace>();
		packets = new ArrayList<MACPacket>();
		nodes = createNodesInOrder(6);
		
		int milliseconds = seconds * 1000;
		
		//one fourth of the traces for each possible flow in random order !
		int routeADCount = traces/4;
		int routeAFCount = traces/4;
		int routeEDCount = traces/4;
		int routeEFCount = traces/4;
		
		//A equals 2000 (index 0)
		//B equals 2001 ...
		//C equals 2002
		//D equals 2003
		//E equals 2004
		//F equals 2005 (index 5)
		
		for(int i = 0; i < traces;i++){
			//select one of the four routes by random
			Node startingNode = null;
			Node endingNode = null;
			while(startingNode == null){
				int choice = (int) (Math.random()*4);
				if(choice == 0 && routeADCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(3);
					routeADCount--;
				} else if(choice == 1 && routeAFCount > 0){
					startingNode = nodes.get(0);
					endingNode = nodes.get(5);
					routeAFCount--;
				} else if(choice == 2 && routeEDCount > 0){
					startingNode = nodes.get(4);
					endingNode = nodes.get(3);
					routeEDCount--;
				} else if(choice == 3 && routeEFCount > 0) {
					startingNode = nodes.get(4);
					endingNode = nodes.get(5);
					routeEFCount--;
				}
			}
			
			//set the starting time for each trace
			int recentMillis = milliseconds/traces * i;
			int recentSeconds = recentMillis / 1000;
			recentMillis = recentMillis % 1000;
			
			//generate special attributes
			
			//create a new comparison trace
			MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
			
			//example data ... not important
			byte[] payload = new byte[]{107,59,0,0,1,58,2,(byte) 133,0,122,46,0,0,0,0,1,1,0,0,0,0,0,0};
			//now use flowLabel to change the payload at position 2,3 and 4
			
			//set all the way by hand, everytime 6 MACPackets
			MACPacket p1 = new MACPacket(false);
			//payload must be set first, because it gets overwritten by other attributes
			p1.setPayload(payload);
			
			p1.setSourceNode(startingNode);
			p1.setDestinationNode(nodes.get(1));

			p1.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p1.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p1.setMicroSeconds(new byte[]{0,0,0,0});
			p1.setLoggedAt(startingNode);
			
			//adding packet one (sent packet)
			startingNode.addSentPackets(p1);
			packets.add(p1);
			tmpTrace.addPacket(p1);
			
			
			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			
			//now second packet
			MACPacket p2 = new MACPacket(false);
			//payload must be set first, because it gets overwritten by other attributes
			p2.setPayload(payload);
			
			p2.setSourceNode(startingNode);
			p2.setDestinationNode(nodes.get(1));
			
			p2.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p2.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p2.setMicroSeconds(new byte[]{0,0,0,0});
			p2.setLoggedAt(nodes.get(1));
			
			//adding packet two (received packet)
			nodes.get(1).addReceivedPackets(p2);
			packets.add(p2);
			tmpTrace.addPacket(p2);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p3 = new MACPacket(false);
			//payload must be set first, because it gets overwritten by other attributes
			p3.setPayload(payload);
					
			p3.setSourceNode(nodes.get(1));
			p3.setDestinationNode(nodes.get(2));
			
			p3.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p3.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p3.setMicroSeconds(new byte[]{0,0,0,0});
			p3.setLoggedAt(nodes.get(1));
			
			//adding packet one (sent packet)
			nodes.get(1).addSentPackets(p3);
			packets.add(p3);
			tmpTrace.addPacket(p3);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}
			
			
			
			//now second packet
			MACPacket p4 = new MACPacket(false);
			//payload must be set first, because it gets overwritten by other attributes
			p4.setPayload(payload);
			
			p4.setSourceNode(nodes.get(1));
			p4.setDestinationNode(nodes.get(2));
			
			p4.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p4.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p4.setMicroSeconds(new byte[]{0,0,0,0});
			p4.setLoggedAt(nodes.get(2));
			
			//adding packet two (received packet)
			nodes.get(2).addReceivedPackets(p4);
			packets.add(p4);
			tmpTrace.addPacket(p4);
			
			//first packet is added
			//update time
			if(recentMillis<900){
				recentMillis += 100;
			} else {
				recentSeconds ++;
				recentMillis -= 900;
			}
			
			MACPacket p5 = new MACPacket(false);
			//payload must be set first, because it gets overwritten by other attributes
			p5.setPayload(payload);
			
			p5.setSourceNode(nodes.get(2));
			p5.setDestinationNode(endingNode);
			
			p5.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p5.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p5.setMicroSeconds(new byte[]{0,0,0,0});
			p5.setLoggedAt(nodes.get(2));
			
			//adding packet one (sent packet)
			nodes.get(2).addSentPackets(p5);
			packets.add(p5);
			tmpTrace.addPacket(p5);

			
			
			//first packet is added
			//update time
			if(recentMillis<500){
				recentMillis += 500;
			} else {
				recentSeconds ++;
				recentMillis -= 500;
			}

			
			
			//now the sixth and last packet
			MACPacket p6 = new MACPacket(false);
			//payload must be set first, because it gets overwritten by other attributes
			p6.setPayload(payload);

			p6.setSourceNode(nodes.get(2));
			p6.setDestinationNode(endingNode);
			
			p6.setSeconds(ByteBuffer.allocate(4).putInt(recentSeconds).array());
			p6.setMilliSeconds(ByteBuffer.allocate(4).putInt(recentMillis).array());
			p6.setMicroSeconds(new byte[]{0,0,0,0});
			p6.setLoggedAt(endingNode);
			
			//adding packet two (received packet)
			endingNode.addReceivedPackets(p6);
			packets.add(p6);
			tmpTrace.addPacket(p6);
			
			compareTraces.add(tmpTrace);
		}
		
		return compareTraces;
	}
	
	/**
	 * Creates nodes from 0x2000 up to 0x20FF,
	 * so shouldn't be used for more than 256 nodes
	 * 
	 * @param number	number of nodes to be created
	 * @return newNodes	the nodes created
	 */
	private ArrayList<Node> createNodesInOrder(int number){
		ArrayList<Node> newNodes = new ArrayList<Node>();
		
		//create 6 nodes from 2000 to 2005
		for(int i = 0; i < number;i++){
			byte[] tmpNodeId = new byte[2];
			tmpNodeId[0] = (byte)0x20;
			tmpNodeId[1] = (byte)i;
			//add new node to nodelist
			Node tmpNode = new Node(tmpNodeId);
			newNodes.add(tmpNode);
		}
		
		return newNodes;
	}
	
	public ArrayList<MACPacket> getPackets(){
		return packets;
	}
	
	public ArrayList<Node> getNodes(){
		return nodes;
	}
}
