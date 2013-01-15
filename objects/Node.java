package packettracking.objects;

import java.util.ArrayList;

public class Node {

	private byte[] nodeId;
	private ArrayList<MACPacket> sentPackets;
	private ArrayList<MACPacket> receivedPackets;
	
	
	
	public Node(byte[] nodeId){
		this.nodeId = nodeId;
		this.sentPackets = new ArrayList<MACPacket>();
		this.receivedPackets = new ArrayList<MACPacket>();
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
}
