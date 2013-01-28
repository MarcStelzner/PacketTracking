package packettracking.model;

import java.util.ArrayList;
import java.util.UUID;

import packettracking.support.Calculator;

public class MultihopPacketTrace {
	
	//The list of packets in the stream, it should be hold chronological
	private ArrayList<MACPacket> packetList; 
	
	//Set FlowLabel
	//every time the counter of flow label gets to the threshold(1024),
	//another Stream with same Flow Label and higher occurrence is created
	private final int flowLabelOccurence; //0 for first occurrence, -1 if not used
	private final int flowLabel; //-1 if not used
	
	//There may be more than one Fragmentation Tags (with Route Over)
	private ArrayList<Integer> fragmentationTags;

	//the time interval of the stream (from first- to lastTime)
	private int firstTime;
	private int firstTimeMilliseconds;
	private int lastTime;
	private int lastTimeMilliseconds;
	
	//TODO: maybe useful as a reference
	private final UUID uuid;
	
	//TODO: which ones of the three are useful ? ---> or other plan to build a path ?
	private Node source;
	private ArrayList<Node> intermediateNodes; // the nodes between the source and the destinations
	private Node destination; //plural, because of (broadcasts, multicasts)

	/**
	 * A Constructor for Messages with a FlowLabel
	 * 
	 * @param label
	 * @param occurrence
	 */
	public MultihopPacketTrace(int label, int occurrence){
		
		//Initializing all global variables
		
		packetList = new ArrayList<MACPacket>();
		
		flowLabelOccurence = occurrence;
		flowLabel = label;
		
		fragmentationTags = new ArrayList<Integer>();
		
		// no time, because no packet yet
		firstTime = -1;
		firstTimeMilliseconds = -1;
		lastTime = -1; 
		lastTimeMilliseconds = -1;
		
		uuid  = UUID.randomUUID();
	}
	
	/**
	 * Standard constructor without flow label
	 * 
	 * @param label
	 * @param occurrence
	 */
	public MultihopPacketTrace(){
		
		//Initializing all global variables
		
		packetList = new ArrayList<MACPacket>();
		
		flowLabelOccurence = -1;
		flowLabel = -1;
		
		fragmentationTags = new ArrayList<Integer>(); //fragmentation not used
		
		// no time, because no packet yet
		firstTime = -1;
		firstTimeMilliseconds = -1;
		lastTime = -1; 
		lastTimeMilliseconds = -1;
		
		uuid  = UUID.randomUUID();
	}
	
	public int getFlowLabelOccurence() {
		return flowLabelOccurence;
	}

	public int getFlowLabel() {
		return flowLabel;
	}
	
	/**
	 * Returns the first 10 bit of the Flow Label, the hashed NodeID
	 * 
	 * @return nodeId
	 */
	public int getFlowLabelId(){
		int flowLabel = getFlowLabel();
		if(flowLabel >= 0){
			//masking 00000000000011111111110000000000 
			//shift them 10 bits to the right:
			return flowLabel >> 10;
		} else {
			return -1;
		}	
	}
	
	/**
	 * Returns the last 10 bit of the Flow Label, the Messagecounter
	 * 
	 * @return counter
	 */
	public int getFlowLabelCount(){
		int flowLabel = getFlowLabel();
		if(flowLabel >= 0){
			// masking 00000000000000000000001111111111 
			// get the last ten bits by modulo operation
			return (flowLabel % 1024);
		} else {
			return -1;
		}	
	}

	public int getFirstTime() {
		return firstTime;
	}
	
//	public void setFirstTime(int firstTime) {
//		this.firstTime = firstTime;
//	}
	
	public int getFirstTimeMilliseconds() {
		return firstTimeMilliseconds;
	}
	
//	public void setFirstTimeMilliseconds(int firstTimeMilliseconds) {
//		this.firstTimeMilliseconds = firstTimeMilliseconds;
//	}

	public int getLastTime() {
		return lastTime;
	}
	
//	public void setLastTime(int lastTime) {
//		this.lastTime = lastTime;
//	}
	
	public int getLastTimeMilliseconds() {
		return lastTimeMilliseconds;
	}
	
//	public void setLastTimeMilliseconds(int lastTimeMilliseconds) {
//		this.lastTimeMilliseconds = lastTimeMilliseconds;
//	}
	
	public Node getSource(){
		return source;
	}
	
	public void setSource(Node source){
		this.source = source;
	}
	
	public ArrayList<Node> getIntermediateNodes(){
		return intermediateNodes;
	}
	
	public void setIntermediateNodes(ArrayList<Node>  intermediateNodes){
		this.intermediateNodes = intermediateNodes;
	}
	
	public Node getDestination(){
		return destination;
	}
	
	public void setDestination(Node destination){
		this.destination = destination;
	}

	
	public UUID getUuid() {
		return uuid;
	}

	/**
	 * This method adds a Packet to the Stream and performs some analyzing to set other parameters in the stream:
	 * - check/set Fragmentation Datagam Tag
	 * - check/set firstTime
	 * - check/set lastTime
	 * 
	 * @param packet
	 */
	public void addPacket(MACPacket packet){
		int packetSeconds = Calculator.byteArrayToInt(packet.getSeconds());
		int packetMilliSeconds = Calculator.byteArrayToInt(packet.getMilliSeconds());
		
		//if there is no first time or the new first Time is earlier, than renew it
		if(firstTime < 0 || firstTime > packetSeconds 
				|| ((firstTime == packetSeconds)&&(firstTimeMilliseconds > packetMilliSeconds))){
			firstTime = packetSeconds;
			firstTimeMilliseconds = packetMilliSeconds;
		}
		
		//if there is no last time or the new first Time is earlier, than renew it
		if(lastTime < packetSeconds 
				|| ((lastTime == packetSeconds)&&(lastTime < packetMilliSeconds))){
			lastTime = packetSeconds;
			lastTimeMilliseconds = packetMilliSeconds;
		}
		
		//at last, add fragmentation tag to the list if there's (a new) one 
		int packetTag = packet.getFragmentationTag();
		if(packetTag > 0){
			boolean exists = false;
			for(int tag : fragmentationTags){
				if(tag == packetTag){
					exists = true;
				}
			}
			if(!exists){
				fragmentationTags.add(packetTag);
			}
		}
		
		//at last, add the packet
		packetList.add(packet);
	}
	
	public ArrayList<MACPacket> getPacketList() {
		return packetList;
	}

	public ArrayList<Integer> getFragmentationTags() {
		return fragmentationTags;
	}
	
	public String toString(){
		String traceToString = "Packet trace startet at a time of " + firstTime + " and ended at a time of " + lastTime + ".\n" 
							+ "It has the flowlabel "+flowLabel+ ".\n"
							+ "The trace's originator: "
							+ source.toString() +"\n"
							+ "The final destination of the trace was: "
							+ destination.toString() +"\n"
							+ "The "+intermediateNodes.size()+" intermediate nodes on the way are the following: \n";
		for(Node n : intermediateNodes){
			traceToString += n.toString() + "\n";
		}
		traceToString += "The trace consists of the following "+packetList.size()+" packet(s): \n";
		for(MACPacket p : packetList){
			traceToString += p.toString();
		}
		traceToString += "This was all information of the trace.\n\n";
		
		
		return traceToString;
	}
}
