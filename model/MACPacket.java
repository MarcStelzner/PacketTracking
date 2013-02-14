package packettracking.model;

import java.nio.ByteBuffer;

import packettracking.utils.Calculator;

public class MACPacket  implements Comparable<MACPacket>{
	
	//boolean to tell if the packet eventually has additional protocol-information
	private boolean protocols;
	
	//Declare Packet-Parameters as defined for Pcap
	private byte[] seconds;
	private byte[] microSeconds;
	private byte[] includingLength;	
	private byte[] originalLength;	
	
	//Declare Parameters for MAC Frame
	private byte[] frameControl;
	private byte sequenceNumber;
	private byte[] sourcePAN; //TODO: not used, maybe in node ? 
	private Node sourceNode;
	private byte[] destinationPAN; //TODO: not used, maybe in node ?
	private Node destinationNode;

	//Declare Payload of the packet
	private byte[] payload;
	
	//Variables not written to pcap:
	private boolean isReceived; //if true, message is logged by receiver, else it's logged by the sender
	private byte[] milliSeconds; //additional time parameter the wiselib uses
	private MultihopPacketTrace accordingStream; //each Node has exactly one according stream
	private SixLoWPANPacket sixLoWPANpacket; //is created, if content is a sixlowpanpacket
	private int linkMetric; //link quality between the nodes ( if(!isReceived) --> linkMetric == 0 ), TODO: not used
	private Node loggingNode; //because the destination does not always match the receivers address (broadcast) if received
	
	
	public MACPacket(boolean protocols){
		this.protocols = protocols;
		sixLoWPANpacket = null;
	}

	public byte[] getSeconds() {
		return seconds;
	}

	public void setSeconds(byte[] seconds) {
		this.seconds = seconds;
	}
	
	public byte[] getMilliSeconds() {
		return milliSeconds;
	}

	public void setMilliSeconds(byte[] milliSeconds) {
		this.milliSeconds = milliSeconds;
	}

	public byte[] getMicroSeconds() {
		return microSeconds;
	}

	public void setMicroSeconds(byte[] microSeconds) {
		this.microSeconds = microSeconds;
	}

	public byte[] getIncludingLength() {
		return includingLength;
	}

	public void setIncludingLength(byte[] includingLength) {
		this.includingLength = includingLength;
	}

	public byte[] getOriginalLength() {
		return originalLength;
	}

	public void setOriginalLength(byte[] originalLength) {
		this.originalLength = originalLength;
	}
	
	public Node getLoggedAt() {
		return loggingNode;
	}

	public void setLoggedAt(Node loggingNode) {
		this.loggingNode = loggingNode;
	}

	public byte[] getSourcePAN() {
		return sourcePAN;
	}

	public void setSourcePAN(byte[] sourcePAN) {
		this.sourcePAN = sourcePAN;
	}
	
	public Node getSourceNode() {
		return sourceNode;
	}

	public void setSourceNode(Node sourceNode) {
		this.sourceNode = sourceNode;
	}
	
	public byte[] getDestinationPAN() {
		return destinationPAN;
	}

	public void setDestinationPAN(byte[] destinationPAN) {
		this.destinationPAN = destinationPAN;
	}

	public Node getDestinationNode() {
		return destinationNode;
	}

	public void setDestinationNode(Node destinationNode) {
		this.destinationNode = destinationNode;
	}

	/**
	 * Get Originator either from Mesh Header or 6LoWPAN compressed header
	 * 
	 * @return originator address
	 */
	public byte[] getOriginator() {
		//return mesh address if available
		if(sixLoWPANpacket != null && sixLoWPANpacket.isMeshHeader()){
			return sixLoWPANpacket.getOriginatorAddress();
		//else look for an existing sixlowpan address
		} else if(sixLoWPANpacket != null && sixLoWPANpacket.isIphcHeader() && sixLoWPANpacket.getSource() != null){
			return sixLoWPANpacket.getSource();
			//otherwise it's really just null
		} else {
			return null;
		}
	}
	
	/**
	 * Get Originator either from Mesh Header or 6LoWPAN compressed header
	 * 
	 * @return originator address
	 */
	public byte[] getFinalDestination() {
		//return mesh address if available
		if(sixLoWPANpacket != null && sixLoWPANpacket.isMeshHeader()){
			return sixLoWPANpacket.getFinalAddress();
		//else look for an existing sixlowpan address
		} else if(sixLoWPANpacket != null && sixLoWPANpacket.isIphcHeader() 
				&& sixLoWPANpacket.getDestination() != null){
			return sixLoWPANpacket.getDestination();
		//otherwise it's really just null
		} else {
			return null;
		}
	}
	
	public byte[] getPayload() {
		return payload;
	}
	
	public int getPayloadSize() {
		return payload.length;
	}

	/**
	 * This Method sets the Payload of the MAC-Layer packet
	 * 
	 * @param payload
	 */
	public void setPayload(byte[] payload) {
		this.payload = new byte[payload.length];
		this.payload = payload;
		
		//if protocols used, get additional information
		if(protocols){
			//check for 6lowpan-packet
			//if 10xxxxxxxx or 11000xxx or 11100xxx or 011xxxxx ---> create a 6lowpan-Packet
			byte firstByte = payload[0];
			int meshAddressingMaskedByte = (firstByte&(byte)192) & 0xFF;
			int fragmentationMaskedByte = (firstByte&(byte)248) & 0xFF;
			int iphcMaskedByte = (firstByte&(byte)224) & 0xFF;
			
			//check for any matching mask
			if(meshAddressingMaskedByte == 128 || fragmentationMaskedByte == 192 
					|| fragmentationMaskedByte == 224 || iphcMaskedByte == 96){
				sixLoWPANpacket = new SixLoWPANPacket(payload);
			}
		}
	}

	public int getFragmentationSize() {
		if(sixLoWPANpacket != null && (sixLoWPANpacket.isFragmentationFirstHeader()||sixLoWPANpacket.isFragmentationSubsequentHeader())){
			return sixLoWPANpacket.getDatagramSize();
		} else {
			return -1;
		}
	}

	public byte[] getFrameControl() {
		return frameControl;
	}

	public void setFrameControl(byte[] frameControl) {
		this.frameControl = frameControl;
	}

	public byte getSequenceNumber() {
		return sequenceNumber;
	}

	public void setSequenceNumber(byte sequenceNumber) {
		this.sequenceNumber = sequenceNumber;
	}
	
	public boolean isReceived() {
		return isReceived;
	}

	public void setReceived(boolean isReceived) {
		this.isReceived = isReceived;
	}
	
	public int getLinkMetric() {
		return linkMetric;
	}

	public void setLinkMetric(int linkMetric) {
		this.linkMetric = linkMetric;
	}
	
	
	/**
	 * Returns a FlowLabel, if there is one existing in the payload
	 * 
	 * @return flowLabel, -1 means no flowLabel
	 */
	public int getFlowLabel() {
		if(sixLoWPANpacket != null && sixLoWPANpacket.isIphcHeader() && sixLoWPANpacket.getTf() < 2){
			return sixLoWPANpacket.getFlowLabel();
		} else {
			return -1;
		}
	}
	
	/**
	 * Returns true for an existing IPHC header, false if theres none or even no sixLoWPANpacket
	 * 
	 * @return boolean, true for IPHC existing
	 */
	public boolean isIPHC() {
		if(sixLoWPANpacket != null && sixLoWPANpacket.isIphcHeader()){
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * TODO: TESTMETHOD
	 */
	public void setFlowLabel(int flowLabel) {
		sixLoWPANpacket.setFlowLabel(flowLabel);
	}
	
	/**
	 * TODO: TESTMETHOD
	 */
	public void setIPHC(boolean iphc) {
		sixLoWPANpacket.setIPHC(iphc);
	}
	
	/**
	 * TODO: TESTMETHOD
	 */
	public void setOriginator(byte[] originator) {
		sixLoWPANpacket.setOriginator(originator);
	}

	/**
	 * TODO: TESTMETHOD
	 */
	public void setFinalDestination(byte[] finalDestination) {
		sixLoWPANpacket.setFinalDestination(finalDestination);
	}

	/**
	 * Returns a FragmentationTag, if there is one existing in the payload
	 * 
	 * @return fragmentationTag, -1 means no fragmentationTag
	 */
	public int getFragmentationTag() {
		if(sixLoWPANpacket != null && (sixLoWPANpacket.isFragmentationFirstHeader()||sixLoWPANpacket.isFragmentationSubsequentHeader())){
			return sixLoWPANpacket.getDatagramTag();
		} else {
			return -1;
		}
	}
	
	public MultihopPacketTrace getAccordingStream() {
		return accordingStream;
	}

	public void setAccordingStream(MultihopPacketTrace accordingStream) {
		this.accordingStream = accordingStream;
	}
	
	@Override
	public int compareTo(MACPacket p)
	{
		int seconds = 0;
		int pSeconds = 0;
		int milliSeconds = 0;
		int pMilliSeconds = 0;
		int microSeconds = 0;
		int pMicroSeconds = 0;
		
		for(int i = 0 ; i < this.seconds.length ; i++){
			seconds += (this.seconds[i] << ((this.seconds.length-1-i)*8)) & 0xFF;
		}
		for(int i = 0 ; i < p.getSeconds().length ; i++){
			pSeconds += (p.getSeconds()[i] << ((p.getSeconds().length-1-i)*8)) & 0xFF;
		}
		for(int i = 0 ; i < this.milliSeconds.length ; i++){
			milliSeconds += (this.milliSeconds[i] << ((this.milliSeconds.length-1-i)*8)) & 0xFF;
		}
		for(int i = 0 ; i < p.getMilliSeconds().length ; i++){
			pMilliSeconds += (p.getMilliSeconds()[i] << ((p.getMilliSeconds().length-1-i)*8)) & 0xFF;
		}
		for(int i = 0 ; i < this.microSeconds.length ; i++){
			microSeconds += (this.microSeconds[i] << ((this.microSeconds.length-1-i)*8)) & 0xFF;
		}
		for(int i = 0 ; i < p.getMicroSeconds().length ; i++){
			pMicroSeconds += (p.getMicroSeconds()[i] << ((p.getMicroSeconds().length-1-i)*8)) & 0xFF;
		}
		
		//get all seconds into one time of long and after subtraction back to int
		long time = (seconds*1000)*1000 + milliSeconds*1000 + microSeconds;
		long pTime = (pSeconds*1000)*1000 + pMilliSeconds*1000 + pMicroSeconds;
		time = time -pTime;
		int intTime = (int)time;
		
	    return intTime;
	}
	
	public String toString(){
		String packetToString = "Packet from " + sourceNode.toString() +"\n"
									+ "        was sent to " + destinationNode.toString() +"\n"
									+ "        and logged at " + loggingNode.toString() +"\n"
									+ "        at a time of " + Calculator.byteArrayToInt(seconds)+"."
									+ "        It has a size of " + getPayloadSize() +". \n";
		if(sixLoWPANpacket != null){
			packetToString += "   The packet contains additional 6LoWPAN information: \n" +
					"        FlowLabel: "+getFlowLabel()+", Fragmentation Tag: "+getFragmentationTag()+" \n";
		} else {
			packetToString += "\n";
		}
		
		return packetToString;
	}
	
	public byte[] toBytes(){ 
		//length :
		//16 for Pcap-Packet, 
		//7 for MAC frame control(2), sequence number(1), panID(4)
		//4 or 16 for address (16 or 64 bit)
		int destinationSourceLength = destinationNode.getNodeId().length;
		byte[] output = new byte[(23+(destinationSourceLength*2)+getPayload().length)];
		
		//put everything together in one byteArray
		
		//first pcap-packet
		System.arraycopy(getSeconds(), 0, output, 0, 4);
		//for microseconds, combine milli and micro:
		int tmpMilli = Calculator.byteArrayToInt(getMilliSeconds());
		int tmpMicro = Calculator.byteArrayToInt(getMicroSeconds());
		tmpMicro += (tmpMilli*1000);
		byte[] tmpMicroByte = ByteBuffer.allocate(4).putInt(tmpMicro).array();
		System.arraycopy(tmpMicroByte, 0, output, 4, 4);
		//2 empty entries for length to fill space
		output[8] = (byte) 0; output[9] = (byte) 0;
		System.arraycopy(getIncludingLength(), 0, output, 10, 2);
		//2 empty entries for length
		output[12] = (byte) 0; output[13] = (byte) 0;
		System.arraycopy(getOriginalLength(), 0, output, 14, 2);
		
		//now MAC Frame (bits are in wrong order)
		System.arraycopy(getFrameControl(), 0, output, 16, 2);
		output[18] = getSequenceNumber();
		//Destination and Source needs to be switched and set according to length
		output[19] = getDestinationPAN()[1];
		output[20] = getDestinationPAN()[0];
		for(int i = destinationSourceLength-1 ; i >= 0 ; i--){
			output[20+destinationSourceLength-i] = destinationNode.getNodeId()[i];
		}
		output[20+destinationSourceLength+1] = getSourcePAN()[1];
		output[20+destinationSourceLength+2] = getSourcePAN()[0];
		for(int i = destinationSourceLength-1 ; i >= 0 ; i--){
			output[20+2+(destinationSourceLength*2)-i] = sourceNode.getNodeId()[i];
		}
		
		//payload
		System.arraycopy(getPayload(), 0, output, 20+2+destinationSourceLength*2+1, getPayload().length);
	
		return output;
	}
}
