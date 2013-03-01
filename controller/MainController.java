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

/**
 * The core-class of the analzyer, iterating through the application
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-15        
 */
public class MainController {
	
	//declaring lists of packets, nodes and traces will be filled with all created objects
	ArrayList<MACPacket> packets;
	ArrayList<Node> nodes;
	ArrayList<MultihopPacketTrace> traces;
	
	public MainController(){		 
	}
	
	/**
	 * Main method of the packettracking analyzer,
	 * coordinating the flow of the program and printing out the results.
	 */
	public void run(boolean testRun, int timeBetweenTraces){
		//set this variable to true for evaluation of testData
		packets = new ArrayList<MACPacket>();
		nodes = new ArrayList<Node>();
		
		//testRun runs tests and quits
		if(testRun){
			useTestData(timeBetweenTraces);
			//quit after running the tests
			System.exit(1);
		}
		
		//run decoder to parse an inputfile for real input
		Decoder reader = new Decoder(); 
		reader.readData();
		packets = reader.getPackets();
		nodes = reader.getNodes();

		
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
		Encoder writer = new Encoder(); 
		writer.printPcapFile(packets);
		
		//Get and sort all packets to traces by double-linking between packets, nodes and traces
		TraceAnalyzer analyzer = new TraceAnalyzer(timeBetweenTraces);		
		traces = analyzer.setUpTraces(packets, nodes);
		
		//Short status report
		System.out.println("\n//////////////////////////////////////////");
		System.out.println("Systemstatus after complete object creation: ");
		System.out.println("Number of Nodes: " + nodes.size());
		System.out.println("Number of Packets: " + packets.size());
		System.out.println("Number of Traces: " + traces.size());	
		System.out.println("//////////////////////////////////////////");
		
		//create a CLI to allow additional user-requests
		MainViewCLI cli = new MainViewCLI(this);
		cli.displayTraces(traces);
		cli.runCLI();

		System.exit(1);
	}
	
	/**
	 * This method uses the TestDataCreator to create fake nodes and packets 
	 * to check performance of the application
	 * 
	 * @param timeBetweenTraces
	 */
	private void useTestData(int timeBetweenTraces){
		/*
		 * First part are performance tests for runtime-efficiency
		 */
		
		// different setups for time evaluation 
		// this was for explicit packetnumber, hops and time
//		int[] traceNumbers = new int[]{100,1000,5000,10000,20000};
//		int[] hops = new int[]{2,10,20};
//		int[] seconds = new int[]{30,600,7200};
		
		// this setup was for explicit packetnumber and hops, but seconds is packets per second
		int[] traceNumbers = new int[]{1000,5000,10000,15000,20000,25000,30000};
		int[] hops = new int[]{2};
		int[] seconds = new int[]{100,250,500};
		
		//do some runs to warm up the JIT-compiler
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
			//... and after analyze check the runtime
			Date after = new Date();
			after.compareTo(before);
			int differenceInMS = (int)(after.getTime() - before.getTime()); 
			System.out.println("Iteration "+l+" takes: "+differenceInMS+" ms to calculate.");
		}
		
		//start the runs for time evaluation
		for(int i = 0; i < traceNumbers.length; i++){
			for(int j = 0; j < hops.length; j++){
				for (int k = 0; k < seconds.length; k++){
					//10 runs for the average
					int averageTime = 0;
					for(int l = 0; l < 10 ; l++){
						System.gc();
						TestDataCreator creator = new TestDataCreator();
//						creator.createTimeTraces(traceNumbers[i], hops[j], seconds[k]); //to test packets over explicit time
						creator.createTimeTraces(traceNumbers[i], hops[j], traceNumbers[i]/seconds[k]); //to test packets per second
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
//					System.out.println("Average of 10 iterations with "+traceNumbers[i]+" traces, "+hops[j]+" hops in "+seconds[k]+" seconds is: "+averageTime/10);
					System.out.println("Average of 10 iterations with "+traceNumbers[i]+" traces, "+hops[j]+" hops in "+traceNumbers[i]/seconds[k]+" seconds is: "+averageTime/10);
					System.out.println("\n");
				}
			}
		}
		
		/*
		 * Second part are functionality tests to check correct tracking behaviour
		 */
		
		/*
		//test-parameters to create traces in explicit time interval
		int[] seconds = new int[]{1,10,30,60};
		int[] traceNumbers = new int[]{12,100,500,1000,4000};
		
		for(int i = 0; i < seconds.length; i++){
			for(int j = 0; j < traceNumbers.length; j++){
				//get all the needed testData
				TestDataCreator creator = new TestDataCreator();
				//create packets with different information
				ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesFull(seconds[i], traceNumbers[j]);
//				ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesFullFrag(seconds[i], traceNumbers[j]);
//				ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesFlow(seconds[i], traceNumbers[j]);
//				ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesStartEnd(seconds[i], traceNumbers[j]);
//				ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesStartEndFrag(seconds[i], traceNumbers[j]);
//				ArrayList<MultihopPacketTrace> compareTraces = creator.createGoodTracesNothing(seconds[i], traceNumbers[j]);
				packets = creator.getPackets();
				
				nodes = creator.getNodes();
				Collections.sort(packets);
				
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
				
				// check correctness of the results
				// comparing all packets of the traces for a match
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
	}
	
	/*
	 *  ------- Operations from the calling view - start -------
	 */
	
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
	
	// ---------------------------------------------------------
	
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
	
	// ---------------------------------------------------------
	
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
	
	// ---------------------------------------------------------
	
	/**
	 * List all traces where the reception was detected by the destination
	 * 
	 * @return
	 */
	public ArrayList<MultihopPacketTrace> finishedTraces(boolean broadcast){
		ArrayList<MultihopPacketTrace> results = new ArrayList<MultihopPacketTrace>();
		for(MultihopPacketTrace t : traces){
			for(MACPacket p : t.getPacketList()){
				//if it matches, add to the list
				if((p.getDestinationNode().equals(t.getDestination()) &&  p.getLoggedAt().equals(t.getDestination())) 
						|| (p.getDestinationNode().isBroadcast() && broadcast)){
					results.add(t);
					break;
				}
			}
		}	
		return results;
	}
	
	// ---------------------------------------------------------
	
	/**
	 * List all traces where the reception wasn't detected by the destination
	 * 
	 * @return
	 */
	public ArrayList<MultihopPacketTrace> unfinishedTraces(){
		//subtract unfinished traces from all traces
		ArrayList<MultihopPacketTrace> finished = finishedTraces(true);
		ArrayList<MultihopPacketTrace> results = new ArrayList<MultihopPacketTrace>();
		results.addAll(traces);
		results.removeAll(finished);
		return results;
	}
	
	/*
	 *  ------- Operations from the calling view - end -------
	 */
}