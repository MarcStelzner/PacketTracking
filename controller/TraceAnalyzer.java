package packettracking.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import packettracking.model.MACPacket;
import packettracking.model.MultihopPacketTrace;
import packettracking.model.Node;
import packettracking.support.Calculator;

public class TraceAnalyzer {

	public TraceAnalyzer(){
		
	}
	
	public ArrayList<MultihopPacketTrace> setUpTraces(ArrayList<MACPacket> packets, ArrayList<Node> nodes){
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
	
	/**
	 * This is the basic method to create all traces, not all information is set yet
	 * 
	 * @param packets
	 * @return initial trace list
	 */
	private ArrayList<MultihopPacketTrace> getTraces(ArrayList<MACPacket> packets){
		ArrayList<MultihopPacketTrace> traces = new ArrayList<MultihopPacketTrace>();
		
		//1. Sort packets to stream by FlowLabel and Fragmentation Header
		ArrayList<MACPacket> checklaterFragmentation = new ArrayList<MACPacket>();
		//timeBetweenTraces is in seconds, TODO: maybe variable by user ? or even better adaptive to number of packets per node/minute
		
		//the time doubled is the secure distance between two traces with same flow label		
		int timeBetweenTraces = 20; 
		
		
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
	
	/**
	 * This method adds all nodes of the trace to the hop-list
	 * 
	 * @param traces
	 */
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
	
	/**
	 * Each trace calculates it's originator and final destination for the packet
	 * 
	 * @param traces
	 * @param nodes
	 */
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
						//this should not happen
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
						m.setSource(m.getPacketList().get(0).getSourceNode());
						m.getIntermediateNodes().remove(m.getPacketList().get(0).getSourceNode());
						m.getPacketList().get(0).getSourceNode().addTraceByOrigin(m);
					}
				}
				//bad, nodes with same hashed id ... get the node which is only transmitting
				//(-BY FLOWLABEL AND ONLY SENDING-)
				else if(foundNodes.size() >= 1){
					ArrayList<Node> foundNodesCopy = new ArrayList<Node>(foundNodes);
					for(MACPacket p : m.getPacketList()){
						Node tmpFoundOne = null;
						for(Node fn : foundNodes){
							if(fn.equals(p.getDestinationNode())){
								tmpFoundOne = fn;
								break;
							}
						}
						foundNodes.remove(tmpFoundOne);
					}
					//now check again
					//(-BY FLOWLABEL AND ONLY SENDING-) found !
					if(foundNodes.size() == 1){
						m.setSource(foundNodes.get(0));
						m.getIntermediateNodes().remove(foundNodes.get(0));
						foundNodes.get(0).addTraceByOrigin(m);
					}
					//(-BY FLOWLABEL AND ONLY SENDING & TIME-)
					else if(foundNodes.size() == 0){
						m.setSource(foundNodesCopy.get(0));
						m.getIntermediateNodes().remove(foundNodesCopy.get(0));
						foundNodesCopy.get(0).addTraceByOrigin(m);
					} 
					//(-BY FLOWLABEL AND ONLY SENDING & TAKE FIRST TIME APPEARANCE-)
					else if(foundNodes.size() >= 1){
						//search for the first packet with the foundNode as Originator
						boolean found = false;
						for(MACPacket p : m.getPacketList()){
							for(Node fn : foundNodes){
								if(p.getSourceNode().equals(fn)){
									m.setSource(fn);
									m.getIntermediateNodes().remove(fn);
									fn.addTraceByOrigin(m);
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
			}
			//no flow label
			//(-BY TIME OF FIRST SOURCE-)
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
