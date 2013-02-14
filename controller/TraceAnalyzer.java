package packettracking.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import packettracking.model.MACPacket;
import packettracking.model.MultihopPacketTrace;
import packettracking.model.Node;
import packettracking.utils.Calculator;

public class TraceAnalyzer {
	
	//timeBetweenTraces is in seconds
	//the time doubled is the secure distance between two traces with same flow label		
	int timeBetweenTraces; 

	public TraceAnalyzer(int timeBetweenTraces){
		this.timeBetweenTraces = timeBetweenTraces; 
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
	
//	/**
//	 * This is the basic method to create all traces, not all information is set yet
//	 * 
//	 * @param packets
//	 * @return initial trace list
//	 */
//	private ArrayList<MultihopPacketTrace> getTracesOld(ArrayList<MACPacket> packets){
//		ArrayList<MultihopPacketTrace> traces = new ArrayList<MultihopPacketTrace>();
//		
//		//1. Sort packets to stream by FlowLabel and Fragmentation Header
//		ArrayList<MACPacket> checklaterFragmentation = new ArrayList<MACPacket>();
//		//timeBetweenTraces is in seconds
//		//the time doubled is the secure distance between two traces with same flow label		
//		int timeBetweenTraces = 3; 
//		
//		
//		for(MACPacket p : packets){
//			int tmpFlowLabel = p.getFlowLabel();
//			int tmpFragmentationTag = p.getFragmentationTag();
//			//is an flow label existing ?
//			if(tmpFlowLabel >= 0){
//				boolean found = false;
//				for(MultihopPacketTrace s : traces){
//					if(s.getFlowLabel() == tmpFlowLabel){
//						//if the flow label matches, check time interval and same originator address
//						if((Calculator.byteArrayToInt(p.getSeconds()) <= s.getLastTime()+timeBetweenTraces 
//								|| (Calculator.byteArrayToInt(p.getSeconds()) == s.getLastTime()+timeBetweenTraces && Calculator.byteArrayToInt(p.getMilliSeconds()) <= s.getLastTimeMilliseconds()))
//								&& (p.getOriginator() == null || Arrays.equals(p.getOriginator(),s.getLongIPSource()))){
//							s.addPacket(p);
//							p.setAccordingStream(s);
//							found = true;
//							break;
//							//look for another stream (next occurrence) or create a new one
//						}
//					}
//				}
//				if(!found){
//					MultihopPacketTrace tmpTrace = new MultihopPacketTrace(tmpFlowLabel);
//					//is the originator of the packet known ?
//					if(p.getOriginator() != null){
//						tmpTrace.setLongIPSource(p.getOriginator());
//					}
//					//is the destination of the packet known ?
//					if(p.getFinalDestination() != null){
//						tmpTrace.setLongIPDestination(p.getFinalDestination());
//					}
//					traces.add(tmpTrace);
//					tmpTrace.addPacket(p);
//					p.setAccordingStream(tmpTrace);
//				}
//			}
//			//no IPHC, but a fragmentation header ... keep the packet for later sorting
//			else if (tmpFragmentationTag > 0 && !p.isIPHC()){
//				//this is done later because a first fragment may get delayed or even lost/not logged 
//				//when checking later the first fragment might have appeared or another one showed up
//				checklaterFragmentation.add(p);
//			}
//			//no flow label or fragmentation tag? try originator and final destination then
//			else{
//				boolean found = false;
//				for(MultihopPacketTrace s : traces){
//					//if the packet knows final destination and originator, trace also, but route does not match, look at next trace
//					if((p.getOriginator() != null && !Arrays.equals(p.getOriginator(),s.getLongIPSource()))
//							 || (p.getFinalDestination() != null && !Arrays.equals(p.getFinalDestination(),s.getLongIPDestination()))){
//						// do nothing
//					}
//					//if route time and payloadsize matches to a packet from stream, packet is found !
//					else if((p.getOriginator() != null && Arrays.equals(p.getOriginator(),s.getLongIPSource()))
//							 && (p.getFinalDestination() != null && Arrays.equals(p.getFinalDestination(),s.getLongIPDestination()))
//							 && (Calculator.byteArrayToInt(p.getSeconds()) <= s.getLastTime()+timeBetweenTraces 
//										|| (Calculator.byteArrayToInt(p.getSeconds()) == s.getLastTime()+timeBetweenTraces && Calculator.byteArrayToInt(p.getMilliSeconds()) <= s.getLastTimeMilliseconds()))
//										&& (p.getPayloadSize() == s.getPacketList().get(0).getPayloadSize())){
//						found = true;
//					}
//					//no originator or final destination ? go the hard way
//					//
//					else if (p.getOriginator() == null || p.getFinalDestination() == null){
//						for(MACPacket sp : s.getPacketList()){
//							// does the packet may be a forwarded packet ? time is matching ?
//							int tmpTimeBetweenStreams = timeBetweenTraces;
//							if(p.getDestinationNode().equals(sp.getDestinationNode())
//									&& p.getSourceNode().equals(sp.getSourceNode())
//									&& p.getPayloadSize() == sp.getPayloadSize()
//									&& (Calculator.byteArrayToInt(p.getSeconds()) <= s.getLastTime()+tmpTimeBetweenStreams 
//									|| (Calculator.byteArrayToInt(p.getSeconds()) == s.getLastTime()+tmpTimeBetweenStreams && Calculator.byteArrayToInt(p.getMilliSeconds()) <= s.getLastTimeMilliseconds()))){
//								found = true;
//								break;
//							}
//						}
//					}
//					if(found){
//						//add packet to stream and break
//						s.addPacket(p);
//						p.setAccordingStream(s);
//						break;
//					}
//				}
//				//no matching trace found ? create a new one
//				if(!found){
//					MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
//					//is the originator of the packet known ?
//					if(p.getOriginator() != null){
//						tmpTrace.setLongIPSource(p.getOriginator());
//					}
//					//is the destination of the packet known ?
//					if(p.getFinalDestination() != null){
//						tmpTrace.setLongIPDestination(p.getFinalDestination());
//					}
//					traces.add(tmpTrace);
//					tmpTrace.addPacket(p);
//					p.setAccordingStream(tmpTrace);
//				}
//			}
//		}
//		
//		//now sort the packets with only a fragmentation header but no flow label to the according streams
//		for(MACPacket p : checklaterFragmentation){
//			int checkLaterTag = p.getFragmentationTag();
//			boolean found = false;
//			for(MultihopPacketTrace s : traces){
//				for(Integer i : s.getFragmentationTags()){
//					//if the tag of the packet is found in a stream ...
//					if(checkLaterTag == i){
//						//... there's the problem of identical tags left, so we have to check for matching packet
//						// from the stream ...
//						for(MACPacket sp : s.getPacketList()){
//							int streamPacketTag = sp.getFragmentationTag();
//							//if tag, sender, receiver, datagramsize, datagram tag and approximately the time matches it's okay
//							//           ---> but it's not easy anyway with first fragment missing, after IP-Hop -> new tag, only mesh-under could be solved
//							if(streamPacketTag == checkLaterTag && p.getDestinationNode().equals(sp.getDestinationNode())
//									&& p.getSourceNode().equals(sp.getSourceNode()) && p.getFragmentationSize() == sp.getFragmentationSize()
//									&& !(Calculator.byteArrayToInt(p.getSeconds()) > (Calculator.byteArrayToInt(sp.getSeconds())+timeBetweenTraces))
//									&& !((Calculator.byteArrayToInt(p.getSeconds())+timeBetweenTraces) < Calculator.byteArrayToInt(sp.getSeconds()))){
//								found = true;
//								s.addPacket(p);
//								p.setAccordingStream(s);
//								break; //get to next packet, no duplicates of packets
//							}
//						}
//					}
//					if(found){
//						break; //... get to next packet
//					}
//				}
//				if(found){
//					break; //... get to next packet
//				}	
//			}
//			//no matching packet with tag found ? --> create new stream
//			if(!found){
//				MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
//				traces.add(tmpTrace);
//				tmpTrace.addPacket(p);
//				p.setAccordingStream(tmpTrace);
//			}
//		}
//		
//		return traces;
//	}
	
	
	
	/**
	 * This is the basic method to create all traces, not all information is set yet
	 * 
	 * @param packets
	 * @return initial trace list
	 */
	private ArrayList<MultihopPacketTrace> getTraces(ArrayList<MACPacket> packets){
		ArrayList<MultihopPacketTrace> openTraces = new ArrayList<MultihopPacketTrace>();
		
		//1. Sort packets to stream by FlowLabel and Fragmentation Header
		ArrayList<MACPacket> checklaterFragmentation = new ArrayList<MACPacket>();
		
		ArrayList<MultihopPacketTrace> tmpFinishedTraces = new ArrayList<MultihopPacketTrace>();
		
		for(MACPacket p : packets){
			int tmpFlowLabel = p.getFlowLabel();
			int tmpFragmentationTag = p.getFragmentationTag();
			
			//shorten the list by traces not matching the time anymore
			ArrayList<MultihopPacketTrace> newlyFinishedTraces = new ArrayList<MultihopPacketTrace>();
			for(MultihopPacketTrace s : openTraces){
				if((Calculator.byteArrayToInt(p.getSeconds()) > s.getLastTime()+timeBetweenTraces )
						|| (Calculator.byteArrayToInt(p.getSeconds()) == s.getLastTime()+timeBetweenTraces && Calculator.byteArrayToInt(p.getMilliSeconds()) > s.getLastTimeMilliseconds())){
					//not matching anymore, put it to temporary DONE list
					newlyFinishedTraces.add(s);
				}
			}
			//out of the loop, renew list
//			System.out.println("newlyFinishedTraces old:" + tmpFinishedTraces.size());
			tmpFinishedTraces.addAll(newlyFinishedTraces);
//			System.out.println("newlyFinishedTraces new:" + tmpFinishedTraces.size());
//			System.out.println("openTraces old:" + openTraces.size());
			openTraces.removeAll(newlyFinishedTraces);
//			System.out.println("openTraces new:" + openTraces.size());
			
			//no IPHC, but a fragmentation header ... keep the packet for later sorting
			if (tmpFragmentationTag > 0 && !p.isIPHC()){
				//this is done later because a first fragment may get delayed or even lost/not logged 
				//when checking later the first fragment might have appeared or another one showed up
				checklaterFragmentation.add(p);
			} else {
				//is an flow label existing ?
				if(tmpFlowLabel >= 0){
					boolean found = false;
					for(MultihopPacketTrace s : openTraces){
						if(s.getFlowLabel() == tmpFlowLabel){
							//if the flow label matches and same originator address
							if(p.getOriginator() == null || Arrays.equals(p.getOriginator(),s.getLongIPSource())){
								s.addPacket(p);
								p.setAccordingStream(s);
								found = true;
								break;
								//look for another stream (next occurrence) or create a new one
							}
						}
					}
					if(!found){
						MultihopPacketTrace tmpTrace = new MultihopPacketTrace(tmpFlowLabel);
						//is the originator of the packet known ?
						if(p.getOriginator() != null){
							tmpTrace.setLongIPSource(p.getOriginator());
						}
						//is the destination of the packet known ?
						if(p.getFinalDestination() != null){
							tmpTrace.setLongIPDestination(p.getFinalDestination());
						}
						openTraces.add(tmpTrace);
						tmpTrace.addPacket(p);
						p.setAccordingStream(tmpTrace);
					}
				}
				//no flow label or fragmentation tag? try originator and final destination then
				else{
					boolean found = false;
					for(MultihopPacketTrace s : openTraces){
						//if the packet knows final destination and originator, trace also, but route does not match, look at next trace
						if((p.getOriginator() != null && !Arrays.equals(p.getOriginator(),s.getLongIPSource()))
								 || (p.getFinalDestination() != null && !Arrays.equals(p.getFinalDestination(),s.getLongIPDestination()))){
							// do nothing
						}
						//if route and payloadsize matches to a packet from stream, packet is found !
						else if((p.getOriginator() != null && Arrays.equals(p.getOriginator(),s.getLongIPSource()))
								 && (p.getFinalDestination() != null && Arrays.equals(p.getFinalDestination(),s.getLongIPDestination()))
								 && (p.getPayloadSize() == s.getPacketList().get(0).getPayloadSize())){
							found = true;
						}
						//no originator or final destination ? go the hard way
						//
						else if (p.getOriginator() == null || p.getFinalDestination() == null){
							for(MACPacket sp : s.getPacketList()){
								// does the packet may be a forwarded packet ? 
								if(p.getDestinationNode().equals(sp.getDestinationNode())
										&& p.getSourceNode().equals(sp.getSourceNode())
										&& p.getPayloadSize() == sp.getPayloadSize()){
									found = true;
									break;
								}
							}
						}
						if(found){
							//add packet to stream and break
							s.addPacket(p);
							p.setAccordingStream(s);
							break;
						}
					}
					//no matching trace found ? create a new one
					if(!found){
						MultihopPacketTrace tmpTrace = new MultihopPacketTrace();
						//is the originator of the packet known ?
						if(p.getOriginator() != null){
							tmpTrace.setLongIPSource(p.getOriginator());
						}
						//is the destination of the packet known ?
						if(p.getFinalDestination() != null){
							tmpTrace.setLongIPDestination(p.getFinalDestination());
						}
						openTraces.add(tmpTrace);
						tmpTrace.addPacket(p);
						p.setAccordingStream(tmpTrace);
					}
				}
			}
		}
		
		//put all other open traces to finished
		tmpFinishedTraces.addAll(openTraces);
		//a list for the finalized traces
		ArrayList<MultihopPacketTrace> finalFinishedTraces = new ArrayList<MultihopPacketTrace>();
		
		//now sort the packets with only a fragmentation header but no flow label to the according streams
		for(MACPacket p : checklaterFragmentation){
			
			//shorten the list by traces not matching the time anymore
			ArrayList<MultihopPacketTrace> newlyFinishedTraces = new ArrayList<MultihopPacketTrace>();
			for(MultihopPacketTrace s : tmpFinishedTraces){
				if((Calculator.byteArrayToInt(p.getSeconds()) > s.getLastTime()+timeBetweenTraces )
						|| (Calculator.byteArrayToInt(p.getSeconds()) == s.getLastTime()+timeBetweenTraces && Calculator.byteArrayToInt(p.getMilliSeconds()) > s.getLastTimeMilliseconds())){
					//not matching anymore, put it to final DONE list
					newlyFinishedTraces.add(s);
				}
			}
			//out of the loop, renew list
			finalFinishedTraces.addAll(newlyFinishedTraces);
			tmpFinishedTraces.removeAll(newlyFinishedTraces);
			

			
			int checkLaterTag = p.getFragmentationTag();
			boolean found = false;
			for(MultihopPacketTrace s : tmpFinishedTraces){
				
				//check if the streams starting time is too far off, than break ... every other trace is further off
				if((Calculator.byteArrayToInt(p.getSeconds()) < s.getFirstTime()-timeBetweenTraces )
						|| (Calculator.byteArrayToInt(p.getSeconds()) == s.getFirstTime()-timeBetweenTraces && Calculator.byteArrayToInt(p.getMilliSeconds()) < s.getFirstTimeMilliseconds())){
					break;
				}
				
				for(Integer i : s.getFragmentationTags()){
					//if the tag of the packet is found in a stream ...
					if(checkLaterTag == i){
						//... there's the problem of identical tags left, so we have to check for matching packet
						// from the stream ...
						for(MACPacket sp : s.getPacketList()){
							int streamPacketTag = sp.getFragmentationTag();
							//if tag, sender, receiver, datagramsize, datagram tag and approximately the time of packets match, it's okay
							//possible problem: on multihop it won't work with one of first fragment missing, all other fragments on this hop are unconnected
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
				tmpFinishedTraces.add(tmpTrace);
				tmpTrace.addPacket(p);
				p.setAccordingStream(tmpTrace);
			}
		}
		
		//put all other open traces to finished
		finalFinishedTraces.addAll(tmpFinishedTraces);
		
		return finalFinishedTraces;
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
			//elide all duplicates
			HashSet<Node> hs = new HashSet<Node>();
			hs.addAll(tmpNodeList);
			tmpNodeList.clear();
			tmpNodeList.addAll(hs);
			m.setIntermediateNodes(tmpNodeList);
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
			
			//does the stream already know it's originator ? 
			Node sourceIsKnown = null;
			//(-BY ALREADY SET-)
			if(m.getLongIPSource() != null){
				//now get the right node by matching
				for(Node n : m.getIntermediateNodes()){
					if(Arrays.equals(n.getNodeId(),Arrays.copyOfRange(m.getLongIPSource(), m.getLongIPSource().length-2, m.getLongIPSource().length))){
						sourceIsKnown = n;
						break;
					}
				}
				
			}
			if(sourceIsKnown != null){
				setSource(m,sourceIsKnown);
			}
			//no originator existing or not found(shouldn't happen), search by other methods
			else{
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
						setSource(m,foundNodes.get(0));
					}
					//no node found --> originatorPacket is not logged (shouldn't happen)
					//check if there is exactly one other node in the network matching it 
					//(-BY ONLY NODE IN NETWORK MATCHING FLOWLABEL (SUSPECTED: PACKETS MISSED LOGGING)-)
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
						//just one ... this should be the real originator
						if(foundNodes.size() == 1){
							setSource(m,foundNodes.get(0));
						}
						//(-ERROR: THIS CANNOT HAPPEN, JUST TAKE FIRST PACKETS SOURCE-)
						else if(foundNodes.size() == 0){
							setSource(m,m.getPacketList().get(0).getSourceNode());
						} 
						//more nodes matching flow label ? guess ...
						//(-PROBLEM: NOT ENOUGH INFORMATION TO DECIDE, GUESS-)
						else if(foundNodes.size() >= 1){
							setSource(m,foundNodes.get(0));
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
							setSource(m,foundNodesCopy.get(0));
						}
						//(-BY FLOWLABEL AND ONLY SENDING & TIME-)
						else if(foundNodes.size() == 0){
							setSource(m,foundNodesCopy.get(0));
						} 
						//(-BY FLOWLABEL AND ONLY SENDING & TAKE FIRST TIME APPEARANCE-)
						else if(foundNodes.size() >= 1){
							//search for the first packet with the foundNode as Originator
							boolean found = false;
							for(MACPacket p : m.getPacketList()){
								for(Node fn : foundNodes){
									if(p.getSourceNode().equals(fn)){
										setSource(m,fn);
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
				else{
					ArrayList<Node> tempReceiver = new ArrayList<Node>();
					ArrayList<Node> tempSourcer = new ArrayList<Node>();
					//(-BY JUST SENDING NODE-)
					for(MACPacket p : m.getPacketList()){
						tempReceiver.add(p.getDestinationNode());
						tempSourcer.add(p.getSourceNode());
					}
					tempSourcer.removeAll(tempReceiver);
					//if just one node is found just sending, thats it!
					if(tempSourcer.size() == 1){
						setSource(m,tempSourcer.get(0));
					}
					//else ... take the last one of the nodes reported
					//(-BY TIME OF FIRST SOURCE-)
					else{
						Node tempNode = m.getPacketList().get(0).getSourceNode();
						setSource(m,tempNode);
					}
				}
			}
			
			
			
			
			
			
			//now get the end ( ------ GET THE DESTINATION OF THE TRACE ------ )
			//if one of the intermediate is broadcast --> destination is broadcast
			//(-BY BROADCAST-)
			Node tempNode = m.getPacketList().get(m.getPacketList().size()-1).getDestinationNode();
			if(tempNode.getNodeId().length == 2 && Arrays.equals(tempNode.getNodeId(), new byte[]{(byte) 0xFF,(byte) 0xFF}) 
					|| tempNode.getNodeId().length == 8 && Arrays.equals(tempNode.getNodeId(), new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF})){
				setDestination(m, tempNode);
			} 
			else {
				//does the stream already know it's final destination ? 
				Node destinationIsKnown = null;
				//(-BY ALREADY SET-)
				if(m.getLongIPDestination() != null){
					//now get the right node by matching
					for(Node n : m.getIntermediateNodes()){
						if(Arrays.equals(n.getNodeId(),Arrays.copyOfRange(m.getLongIPDestination(), m.getLongIPDestination().length-2, m.getLongIPDestination().length))){
							destinationIsKnown = n;
							break;
						}
					}
				}
				if(destinationIsKnown != null){
					setDestination(m, destinationIsKnown);
				}
				//no destination existing or not found(shouldn't happen), search by other methods
				else{
					ArrayList<Node> tempReceiver = new ArrayList<Node>();
					ArrayList<Node> tempSourcer = new ArrayList<Node>();
					//(-BY JUST RECEIVING NODE-)
					for(MACPacket p : m.getPacketList()){
						tempReceiver.add(p.getDestinationNode());
						tempSourcer.add(p.getSourceNode());
					}
					tempReceiver.removeAll(tempSourcer);
					//if just one node is found just receiving, it's good !
					if(tempReceiver.size() == 1){
						setDestination(m, tempReceiver.get(0));
					}
					//else ... take the last one of the nodes reported
					//(-BY LAST NODES DESTINATION-)
					else{
						setDestination(m, tempNode);
					}
				}
			}
		}
	}
	
	/**
	 * Supporting method to set source for trace and trace for the matching node,
	 * also the node is elided from the intermediate nodes list.
	 * 
	 * @param trace
	 * @param node
	 */
	private void setSource(MultihopPacketTrace trace, Node node){
		trace.setSource(node);
		trace.getIntermediateNodes().remove(node);
		node.addTraceByOrigin(trace);
	}
	
	/**
	 * Supporting method to set destination for trace and trace for the matching node,
	 * also the node is elided from the intermediate nodes list.
	 * 
	 * @param trace
	 * @param node
	 */
	private void setDestination(MultihopPacketTrace trace, Node node){
		trace.setDestination(node);
		trace.getIntermediateNodes().remove(node);
		node.addTraceByDestination(trace);
	}
}
