package packettracking.model;

import java.util.ArrayList;

import packettracking.utils.Calculator;

/**
 * A node object holds simple information about the node, like address and location.
 * Lists about sent and received packets allow review of the history.
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-15        
 */
public class Node {
	
	private static final int BROADCAST = 65535;

	private byte[] nodeId;
	private ArrayList<MACPacket> sentPackets;
	private ArrayList<MACPacket> receivedPackets;
	
	private ArrayList<MultihopPacketTrace> tracesByOrigin;
	private ArrayList<MultihopPacketTrace> tracesByDestination;
	
	//is this "node" just a broadcast address ?
	private boolean broadcast;
	
	double x;
	double y;
	double z;

	/**
	 * Standard constructor for sensornode representation
	 * 
	 * @param nodeId the address of the node
	 */
	public Node(byte[] nodeId){
		x = -1;
		y = -1;
		z = -1;
		initializeGlobal(nodeId);
	}
	
	/**
	 * Constructor including coordinates for node-location
	 * 
	 * @param nodeId the address of the node
	 * @param x
	 * @param y
	 * @param z
	 */
	public Node(byte[] nodeId, double x, double y, double z){
		this.x = x;
		this.y = y;
		this.z = z;
		initializeGlobal(nodeId);
	}
	
	/**
	 * Initialization of the variables for the constructors
	 *
	 * @param nodeId the address of the node
	 */
	private void initializeGlobal(byte[] nodeId){
		this.nodeId = nodeId;
		broadcast = false;
		if(Calculator.byteArrayToInt(nodeId)==BROADCAST){
			System.out.println("---------BROADCAST---------");
			broadcast = true;
		}
		this.sentPackets = new ArrayList<MACPacket>();
		this.receivedPackets = new ArrayList<MACPacket>();
		this.tracesByOrigin = new ArrayList<MultihopPacketTrace>();
		this.tracesByDestination = new ArrayList<MultihopPacketTrace>();
	}
	
	/**
	 * Converts the node information into a String.
	 * 
	 * @return nodeToString represents the node as a String
	 */
	@Override
	public String toString(){ 
		String nodeToString = "Node ";
		nodeToString += Calculator.bytesToHex(nodeId);
		//only add node positions, if the exist
		if(x != -1 && y != -1 && z != -1){
			nodeToString += " at the coordinates "+x+" , "+y+" , "+z+" ";
		}
		if(broadcast){
			nodeToString = "Broadcast";
		}
		
		return nodeToString;
	}
	
	/*
	 * GETTERS AND SETTERS FOR ATTRIBUTES
	 */
	
	public byte[] getNodeId() {
		return nodeId;
	}

	public void setNodeId(byte[] nodeId) {
		this.nodeId = nodeId;
	}

	public ArrayList<MACPacket> getSentPackets() {
		return sentPackets;
	}

	public void setSentPackets(ArrayList<MACPacket> sentPackets) {
		this.sentPackets = sentPackets;
	}
	
	public void addSentPackets(MACPacket sentPacket){
		this.sentPackets.add(sentPacket);
	}

	public ArrayList<MACPacket> getReceivedPackets() {
		return receivedPackets;
	}

	public void setReceivedPackets(ArrayList<MACPacket> receivedPackets) {
		this.receivedPackets = receivedPackets;
	}

	public void addReceivedPackets(MACPacket receivedPacket){
		this.receivedPackets.add(receivedPacket);
	}
	
	public void setCoords(double x, double y, double z) {
		this.x = x;
		this.y = y;
		this.z = z;
	}
	
	public double getX() {
		return x;
	}

	public double getY() {
		return y;
	}

	public double getZ() {
		return z;
	}

	public ArrayList<MultihopPacketTrace> getTracesByOrigin() {
		return tracesByOrigin;
	}

	public void addTraceByOrigin(MultihopPacketTrace traceByOrigin) {
		this.tracesByOrigin.add(traceByOrigin);
	}

	public ArrayList<MultihopPacketTrace> getTracesByDestination() {
		return tracesByDestination;
	}

	public void addTraceByDestination(MultihopPacketTrace traceByDestination) {
		this.tracesByDestination.add(traceByDestination);
	}
	
	public boolean isBroadcast(){
		return broadcast;
	}
}
