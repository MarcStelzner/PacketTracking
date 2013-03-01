package packettracking.model;

import java.util.Arrays;

import packettracking.utils.Calculator;

/**
 * This class is designed to give additional information about 6LoWPAN packets,
 * which does not involve IPv6 information yet
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-15        
 */
public class SixLoWPANPacket {
	
	//additional information
	int headerSize; //size of all used 6LoWPAN header
	
	//mesh addressing header
	boolean meshHeader = false;
	boolean vFlag; // true = length of 16 bit instead of 64 for originator address
	boolean fFlag; // true = length of 16 bit instead of 64 for final address
	int hopsLeft;
	byte[] originatorAddress;
	byte[] finalAddress;
	
	//fragmentation header
	boolean fragmentationFirstHeader = false;
	boolean fragmentationSubsequentHeader = false;
	int datagramSize;
	int datagramTag;
	int datagramOffset;
	
	//iphc header
	boolean iphcHeader = false;
	int tf; //Traffic Class and Flow Label (0 = 4 bytes, 1 = 3 bytes, 2 = 1 byte, 0 = bytes after header)
	boolean nh; //next header (0 = carried inline, 1 = encoded in NHC (if theres any))
	int hlim; //hop limit (0 = carried inline, 1 = 1, 2 = 64, 3 = 255)
	boolean cid; //context identifier extension (0 = additional context information, 1 = elided)
	boolean sac; //source address compression
	int sam; //source address mode
	boolean m; // multicast address (0 = no multicast, 1 = destination address is multicast)
	boolean dac; //destination address compression 
	int dam; //destination address mode
	
	//iphc fields
	int ecn; //explicit congestion notification
	int dscp; //differentiated service point
	int flowLabel;
	int nextHeader;
	int hopLimit;
	int contextIdentifierExtension;
	byte[] source;
	byte[] destination;
	
	//the rest is payload
	byte[] payload;
	
	public SixLoWPANPacket(byte[] packet){
		createPacket(packet);
	}
	
	/**
	 * On creating a SixLoWPAN packet, this method will be called to parse the payload into variables.
	 * It checks for existing dispatch header before calling the according subroutine.
	 * 
	 * @param packet payload of the MACPacket to parse
	 */
	private void createPacket(byte[] packet){
		headerSize = 0;
		byte dispatchByte = packet[0];
		
		//1. check for mesh under header
		int maskedByte = (dispatchByte&(byte)192) & 0xFF;
		if(maskedByte == 128){
			meshHeader = true;
			packet = createMeshAddressingHeader(packet);
			dispatchByte = packet[0];
		}
		
		//2.a. check for Fragmentation header
		maskedByte = (dispatchByte&(byte)248) & 0xFF;
		if(maskedByte == 192){
			fragmentationFirstHeader = true;
			packet = createFragmentationFirstHeader(packet);
			dispatchByte = packet[0];
		}
		
		//2.b. check for Fragmentation header
		else if(maskedByte == 224){
			fragmentationSubsequentHeader = true;
			packet = createFragmentationSubsequentHeader(packet);
			dispatchByte = packet[0];
		}
		
		//3. check for IPHC (don't do it, if there was a subsequent fragmentation header)
		maskedByte = (dispatchByte&(byte)224) & 0xFF;
		if(maskedByte == 96 && !fragmentationSubsequentHeader){
			iphcHeader = true;
			packet = createIPHCHeader(packet);

		}
		
		//4. if none of the before worked --> destroy class, wrong generation
		if(!meshHeader && !fragmentationFirstHeader && !fragmentationSubsequentHeader && !iphcHeader){
			try {
				finalize();
			} catch (Throwable e) {
				e.printStackTrace();
			}
		} else {
			payload = packet;
		}
		
		//TODO: Now this payload could be passed to ICMPv6/UDP Header
	}
	
	/**
	 * Starts to parse a mesh addressing header, because an according dispatch header was found.
	 * 
	 * @param packet payload of the MACPacket to parse for mesh header
	 * @return packet as the remaining payload
	 */
	private byte[] createMeshAddressingHeader(byte[] packet){
		int packetPosition = 0;
		byte actualByte = packet[packetPosition];
		
		//check length of originatorAddress (xxYxxxxx)
		int maskedByte = (actualByte&(byte)32) & 0xFF;
		if(maskedByte == 32){
			vFlag = true;
		} else {
			vFlag = false;
		}
		
		//check length of finalAddress (xxYxxxxx)
		maskedByte = (actualByte&(byte)16) & 0xFF;
		if(maskedByte == 16){
			fFlag = true;
		} else {
			fFlag = false;
		}
		
		//get the hops left
		maskedByte = (actualByte&(byte)15) & 0xFF;
		hopsLeft = maskedByte;
		packetPosition ++;
		
		//get orginatorAddress
		if(vFlag){
			originatorAddress = Arrays.copyOfRange(packet, packetPosition, packetPosition+2);
			packetPosition += 2;
		} else {
			originatorAddress = Arrays.copyOfRange(packet, packetPosition, packetPosition+8);
			packetPosition += 8;
		}
		
		//get finalAddress
		if(fFlag){
			finalAddress = Arrays.copyOfRange(packet, packetPosition, packetPosition+2);
			packetPosition += 2;
		} else {
			finalAddress = Arrays.copyOfRange(packet, packetPosition, packetPosition+8);
			packetPosition += 8;
		}
		
		headerSize += packetPosition;
		//return the remaining payload
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	
	/**
	 * Starts to parse a fragmentation first header, because an according dispatch header was found.
	 * The method uses the corporate fragmentation header for parsing in common with the subsequent header.
	 * 
	 * @param packet payload of the MACPacket to parse for fragmentation first header
	 * @return packet as the remaining payload
	 */
	private byte[] createFragmentationFirstHeader(byte[] packet){
		return createCorporateFragmentationHeader(packet);
	}

	/**
	 * Starts to parse a subsequent fragmentation header, because an according dispatch header was found.
	 * The method uses the corporate fragmentation header for parsing in common with the first fragmentation header.
	 * 
	 * @param packet payload of the MACPacket to parse for fragmentation subsequent header
	 * @return packet as the remaining payload
	 */
	private byte[] createFragmentationSubsequentHeader(byte[] packet){
		packet = createCorporateFragmentationHeader(packet);
		int packetPosition = 0;
		//get the datagramOffset
		datagramOffset = Calculator.byteArrayToInt(Arrays.copyOfRange(packet, packetPosition, packetPosition+2));
		packetPosition+=2;
		
		headerSize += packetPosition;	
		//return the remaining payload
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	
	/**
	 * This Method creates the part the first and subsequent header have in common
	 * 
	 * @param packet payload of the MACPacket to parse for a fragmentation header
	 * @return packet as the remaining payload
	 */
	private byte[] createCorporateFragmentationHeader(byte[] packet){
		//the packetPosition marks the index for the actual byte the parser is at
		int packetPosition = 0;
		byte actualByte = packet[packetPosition];
		
		//get the datagramSize
		int maskedByte = (actualByte&(byte)7) & 0xFF;
		datagramSize = (maskedByte << 8) + (packet[packetPosition+1] & 0xFF);
		packetPosition+=2;
		
		//get the datagramTag
		datagramTag = Calculator.byteArrayToInt(Arrays.copyOfRange(packet, packetPosition, packetPosition+2));
		packetPosition+=2;
		
		headerSize += packetPosition;	
		//return the remaining payload
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	

	/**
	 * Starts to parse an IPHC header, because an according dispatch header was found.
	 * 
	 * @param packet payload of the MACPacket to parse for an IPHC header
	 * @return packet as the remaining payload
	 */
	private byte[] createIPHCHeader(byte[] packet){
		//the packetPosition marks the index for the actual byte the parser is at
		int packetPosition = 0;
		byte actualByte = packet[packetPosition];
		//check TF 
		int maskedByte = (actualByte&(byte)24) & 0xFF;
		tf = maskedByte >> 3;
		
		//check NH 
		maskedByte = (actualByte&(byte)4) & 0xFF;
		if(maskedByte == 4){
			nh = true;
		} else {
			nh = false;
		}
		
		//check HLIM
		maskedByte = (actualByte&(byte)3) & 0xFF;
		hlim = maskedByte;
		
		packetPosition++;
		actualByte = packet[packetPosition];
		
		//check CID
		maskedByte = (actualByte&(byte)128) & 0xFF;
		if(maskedByte == 128){
			cid = true;
		} else {
			cid = false;
		}
		
		//check SAC
		maskedByte = (actualByte&(byte)64) & 0xFF;
		if(maskedByte == 64){
			sac = true;
		} else {
			sac = false;
		}
		
		//check SAM 
		maskedByte = (actualByte&(byte)48) & 0xFF;
		sam = maskedByte >> 4;
		
		//check M 
		maskedByte = (actualByte&(byte)8) & 0xFF;
		if(maskedByte == 8){
			m = true;
		} else {
			m = false;
		}
		
		//check DAC 
		maskedByte = (actualByte&(byte)4) & 0xFF;
		if(maskedByte == 4){
			dac = true;
		} else {
			dac = false;
		}
		
		//check DAM
		maskedByte = (actualByte&(byte)3) & 0xFF;
		dam = maskedByte;
		
		packetPosition++;
		actualByte = packet[packetPosition];
		
		/*
		 * Now the iphcContent
		 */
		
		//at first check for tf
		if(tf == 0){
			maskedByte = (actualByte&(byte)192) & 0xFF;
			ecn = maskedByte >> 6;
			maskedByte = (actualByte&(byte)63) & 0xFF;
			dscp = maskedByte;
			
			packetPosition++;
			
			int firstFlowLabelPart = packet[packetPosition] & (byte) 15 & 0xFF;
			int secondFlowLabelPart = packet[packetPosition+1] & 0xFF;
			int thirdFlowLabelPart = packet[packetPosition+2] & 0xFF;
			flowLabel = (firstFlowLabelPart << 16) + (secondFlowLabelPart << 8) + thirdFlowLabelPart;
			
			packetPosition+=3;
		} else if (tf == 1) {
			maskedByte = (actualByte&(byte)192) & 0xFF;
			ecn = maskedByte >> 6;
			
			int firstFlowLabelPart = packet[packetPosition] & (byte) 15 & 0xFF;
			int secondFlowLabelPart = packet[packetPosition+1] & 0xFF;
			int thirdFlowLabelPart = packet[packetPosition+2] & 0xFF;
			flowLabel = (firstFlowLabelPart << 16) + (secondFlowLabelPart << 8) + thirdFlowLabelPart;
			
			packetPosition+=3;
		} else if (tf == 2){
			maskedByte = (actualByte&(byte)192) & 0xFF;
			ecn = maskedByte >> 6;
			maskedByte = (actualByte&(byte)63) & 0xFF;
			dscp = maskedByte;
			
			packetPosition++;
		} //or else there is nothing with tf == 3
		
		
		//now check for nh, if 0, 8 bits carried inline
		if(!nh){
			nextHeader = packet[packetPosition] & 0xFF; 
			packetPosition++;
		}
		
		//check for hop limit
		if(hlim == 0){ //inline
			hopLimit = packet[packetPosition] & 0xFF; 
			packetPosition++;
		} else if(hlim == 1) { //1
			hopLimit = 1;
		} else if(hlim == 2) { //64
			hopLimit = 64;
		} else { //hlim = 3 --> 255
			hopLimit = 255;
		}
		
		//check source address
		if(!sac){ //stateless compression
			if(sam == 0){ //128 bits
				source = Arrays.copyOfRange(packet, packetPosition, packetPosition+16); 
				packetPosition += 16;
			} else if (sam == 1){ //64 bits
				source = Arrays.copyOfRange(packet, packetPosition, packetPosition+8); 
				packetPosition += 8;
			} else if (sam == 2){ //16 bits
				source =Arrays.copyOfRange(packet, packetPosition, packetPosition+2); 
				packetPosition += 2;
			} //else sam == 3 --> 0 bits
		} else { //statefull compression
			if(sam == 0){
				//"unspecified address"
			} else if (sam == 1){ //64 bits
				source = Arrays.copyOfRange(packet, packetPosition, packetPosition+8); 
				packetPosition += 8;
			} else if (sam == 2){ //16 bits
				source = Arrays.copyOfRange(packet, packetPosition, packetPosition+2); 
				packetPosition += 2;
			} //else sam == 3 --> 0 bits		
		}
		
		if(!m){ //no multicast
			if(!dac){ //stateless compression
				if(dam == 0){ //128 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+16); 
					packetPosition += 16;
				} else if (dam == 1){ //64 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+8); 
					packetPosition += 8;
				} else if (dam == 2){ //16 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+2); 
					packetPosition += 2;
				} //else dam == 3 --> 0 bits
			} else { //statefull compression
				if(dam == 0){ 
					//"reserved"
				} else if (dam == 1){ //64 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+8); 
					packetPosition += 8;
				} else if (dam == 2){ //16 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+2); 
					packetPosition += 2;
				} //else dam == 3 --> 0 bits	
			}
		} else { //destination is multicast
			if(!dac){ //stateless compression
				if(dam == 0){ //128 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+16); 
					packetPosition += 16;
				} else if (dam == 1){ //48 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+6); 
					packetPosition += 6;
				} else if (dam == 2){ //32 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+4); 
					packetPosition += 4;
				} else {//dam == 3 --> 8 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+1); 
					packetPosition ++;
				}
			} else { //statefull compression
				if(dam == 0){ //48 bits
					destination = Arrays.copyOfRange(packet, packetPosition, packetPosition+6); 
					packetPosition += 6;
				} //else dam = 1/2/3 --> reserved	
			}
		}
		
		//check for Context Identifier Extension
		if(!cid){
			contextIdentifierExtension = packet[packetPosition] & 0xFF; 
			packetPosition++;
			//additional context for source and destination
		}
		
		//TODO: NHC header parsing, if there is such header, though not important for tracking at this point
		
		headerSize += packetPosition;
		//return the remaining payload
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	
	/*
	 * GETTERS AND SETTERS FOR ATTRIBUTES
	 */

	public int getHeaderSize() {
		return headerSize;
	}

	public boolean isMeshHeader() {
		return meshHeader;
	}

	public boolean isvFlag() {
		return vFlag;
	}

	public boolean isfFlag() {
		return fFlag;
	}

	public int getHopsLeft() {
		return hopsLeft;
	}

	public byte[] getOriginatorAddress() {
		return originatorAddress;
	}

	public byte[] getFinalAddress() {
		return finalAddress;
	}

	public boolean isFragmentationFirstHeader() {
		return fragmentationFirstHeader;
	}

	public boolean isFragmentationSubsequentHeader() {
		return fragmentationSubsequentHeader;
	}

	public int getDatagramSize() {
		return datagramSize;
	}

	public int getDatagramTag() {
		return datagramTag;
	}

	public int getDatagramOffset() {
		return datagramOffset;
	}

	public boolean isIphcHeader() {
		return iphcHeader;
	}

	public int getTf() {
		return tf;
	}

	public boolean isNh() {
		return nh;
	}

	public int getHlim() {
		return hlim;
	}

	public boolean isCid() {
		return cid;
	}

	public boolean isSac() {
		return sac;
	}

	public int getSam() {
		return sam;
	}

	public boolean isM() {
		return m;
	}

	public boolean isDac() {
		return dac;
	}

	public int getDam() {
		return dam;
	}

	public int getEcn() {
		return ecn;
	}

	public int getDscp() {
		return dscp;
	}

	public int getFlowLabel() {
		return flowLabel;
	}

	public int getNextHeader() {
		return nextHeader;
	}

	public int getHopLimit() {
		return hopLimit;
	}

	public int getContextIdentifierExtension() {
		return contextIdentifierExtension;
	}

	public byte[] getSource() {
		return source;
	}

	public byte[] getDestination() {
		return destination;
	}	

	public byte[] getPayload() {
		return payload;
	}
	
	/*
	 * TESTMETHODS - ONLY USED FOR TESTDATACREATOR
	 * needed to get public access to attributes
	 */
	
	public void setFlowLabel(int flowLabel) {
		this.flowLabel = flowLabel;
	}
	
	public void setIPHC(boolean iphc) {
		this.iphcHeader = iphc;
	}

	public void setOriginator(byte[] originator) {
		source = originator;
	}

	public void setFinalDestination(byte[] finalDestination) {
		destination = finalDestination;
	}

	public void setFragmentationFirstHeader(boolean fragFirst) {
		fragmentationFirstHeader = fragFirst;
	}

	public void setFragmentationSubsequentHeader(boolean fragSubsequent) {
		fragmentationSubsequentHeader = fragSubsequent;
	}

	public void setDatagramTag(int datagramTag) {
		this.datagramTag = datagramTag;
	}

	public void setDatagramSize(int datagramSize) {
		this.datagramSize = datagramSize;
	}
}
