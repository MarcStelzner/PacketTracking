package packettracking.objects;
public class MACPacket {
	
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
	private MultihopPacketTrace accordingStream; //each Node has exactly one according stream
	private SixLoWPANpacket sixLoWPANpacket; //is created, if content is a sixlowpanpacket
	
	
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
	 * The "According Node" is the node, where the packet belongs to.
	 * If the logged packet is from the Receiver, it is the Destination,
	 * else if it is logged at the sender, the "According Node" is the Source
	 * @return
	 */
	public Node getAccordingNode() {
		if(isReceived){
			return destinationNode;
		}
		else {
			return sourceNode;
		}
	}

	public byte[] getPayload() {
		return payload;
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
				sixLoWPANpacket = new SixLoWPANpacket(payload);
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
	 * Returns the first 10 bit of the Flow Label, the hashed NodeID
	 * 
	 * @return nodeId
	 */
	public int getFlowLabelId(){
		int flowLabel = getFlowLabel();
		if(flowLabel >= 0){
			//masking 00000000000011111111110000000000 
			//it is done by subtracting the last 10 bits from the first (12 empty highest bits are ignored):
			return (flowLabel - (flowLabel % 1024));
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
	
	public String toString(){
		return "";
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
		System.arraycopy(getMicroSeconds(), 0, output, 4, 4);
		System.arraycopy(getIncludingLength(), 0, output, 8, 4);
		System.arraycopy(getOriginalLength(), 0, output, 12, 4);
		
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
		
//		for (byte b : output) {
//			System.out.format("0x%x ", b);
//		}  
	
		return output;
	}
}
