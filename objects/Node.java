package packettracking.objects;

import java.util.ArrayList;

public class Node {

	private byte[] nodeId; //TODO: is not really address-enough
	private ArrayList<MACPacket> sentPackets;
	private ArrayList<MACPacket> receivedPackets;
	
	private ArrayList<MultihopPacketTrace> tracesByOrigin;
	private ArrayList<MultihopPacketTrace> tracesByDestination;
	
	//Coordinates of the Node, TODO: Maybe as a vector ?
	double x;
	double y;
	double z;

	public Node(byte[] nodeId){
		x = -1;
		y = -1;
		z = -1;
		this.nodeId = nodeId;
		this.sentPackets = new ArrayList<MACPacket>();
		this.receivedPackets = new ArrayList<MACPacket>();
		this.tracesByOrigin = new ArrayList<MultihopPacketTrace>();
		this.tracesByDestination = new ArrayList<MultihopPacketTrace>();
	}
	
	public Node(byte[] nodeId, double x, double y, double z){
		this.x = x;
		this.y = y;
		this.z = z;
		this.nodeId = nodeId;
		this.sentPackets = new ArrayList<MACPacket>();
		this.receivedPackets = new ArrayList<MACPacket>();
		this.tracesByOrigin = new ArrayList<MultihopPacketTrace>();
		this.tracesByDestination = new ArrayList<MultihopPacketTrace>();
	}
	
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
	
	public String toString(){
		String nodeToString = "Node ";
		if(nodeId.length > 2){
			nodeToString += byteArrayToLong(8, nodeId);
		} else {
			nodeToString += byteArrayToInt(2, nodeId);
		}
		nodeToString += " at the coordinates "+x+" , "+y+" , "+z+" ";
		
		return nodeToString;
	}
	
	/**
	 * This Method turns bytearrays of a maximum length of 4 into integer
	 * 
	 * @param length
	 * @param array
	 * @return
	 */
	private int byteArrayToInt(int length, byte[] array){
		int newInt = 0;
		if(length > 4){
			System.out.println("Bytearray is too large with a size of "+length+". Only a length of 4 is possible (32 bit for int). Last "+(length-4)+" bytes will be ignored." );
			length = 4;
		}
		else{
			for(int i = 0 ; i < length ; i++){
				newInt += (array[i] << ((length-1-i)*8)) & 0xFF;
			}
		}
		return newInt;
	}
	
	/**
	 * This Method turns bytearrays of a maximum length of 8 into long
	 * 
	 * @param length
	 * @param array
	 * @return
	 */
	private long byteArrayToLong(int length, byte[] array){
		long newLong = 0;
		if(length > 4){
			System.out.println("Bytearray is too large with a size of "+length+". Only a length of 8 is possible (64 bit for int). Last "+(length-4)+" bytes will be ignored." );
			length = 4;
		}
		else{
			for(int i = 0 ; i < length ; i++){
				newLong += (array[i] << ((length-1-i)*8)) & 0xFF;
			}
		}
		return newLong;
	}
}
