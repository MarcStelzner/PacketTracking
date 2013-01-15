package packettracking.objects;

import java.util.Arrays;

/**
 * This class is designed to give additional information about 6LoWPAN packets,
 * which does not involve IPv6 information yet
 * 
 * @author Marc
 *
 */
public class SixLoWPANpacket {
	
	//additional information
	int headerSize; //size of all used 6LoWPAN header
	
	//mesh addressing header
	boolean meshHeader = false;
	boolean vFlag; // true = length of 16 bit instead of 64 for originator address
	boolean fFlag; // true = length of 16 bit instead of 64 for final address
	int hopsLeft;
	long originatorAddress;
	long finalAddress;
	
	//fragmentation header
	boolean fragmentationFirstHeader = false;
	boolean fragmentationSubsequentHeader = false;
	int datagramSize;
	int datagramTag;
	int datagramOffset;
	
	//iphc header
	boolean iphcHeader = false;
	int tf; //Traffic Class and Flow Label (0 = 4 bytes, 1 = 3 bytes, 2 = 1 byte, 0 = bytes after header)
	boolean nh; //next header --- //TODO: set, but ignored at the moment
	int hlim; //hop limit --- //TODO: set, but ignored at the moment
	boolean cid; //context identifier extension --- //TODO: set, but ignored at the moment
	boolean sac; //source address compression --- //TODO: set, but ignored at the moment
	int sam; //source address mode --- //TODO: set, but ignored at the moment
	boolean m; // multicast address (1 = true) --- //TODO: set, but ignored at the moment
	boolean dac; //destination address compression --- //TODO: set, but ignored at the moment
	int dam; //destination address mode --- //TODO: set, but ignored at the moment
	
	//iphc fields
	int ecn; //explicit congestion notification
	int dscp; //differentiated service point
	int flowLabel;
	
	
	//TODO:every other field not set
	
	
	//the rest is payload
	byte[] payload;
	
	
	
	public SixLoWPANpacket(byte[] packet){
		createPacket(packet);
	}
	
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
//			for (byte b : packet) {
//				System.out.format("0x%x ", b);
//			}
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
		
		//TODO: Now this payload could be passed to IPv6 Header
	}
	
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
			originatorAddress = byteArrayToLong(2,Arrays.copyOfRange(packet, packetPosition, packetPosition+2));
			packetPosition += 2;
		} else {
			originatorAddress = byteArrayToLong(8,Arrays.copyOfRange(packet, packetPosition, packetPosition+8));
			packetPosition += 8;
		}
		
		//get finalAddress
		if(fFlag){
			finalAddress = byteArrayToLong(2,Arrays.copyOfRange(packet, packetPosition, packetPosition+2));
			packetPosition += 2;
		} else {
			finalAddress = byteArrayToLong(8,Arrays.copyOfRange(packet, packetPosition, packetPosition+8));
			packetPosition += 8;
		}
		
		headerSize += packetPosition;
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	
	
	private byte[] createFragmentationFirstHeader(byte[] packet){
		return createCorporateFragmentationHeader(packet);
	}

	private byte[] createFragmentationSubsequentHeader(byte[] packet){
		packet = createCorporateFragmentationHeader(packet);
		int packetPosition = 0;
		
		//get the datagramOffset
		datagramOffset = byteArrayToInt(2,Arrays.copyOfRange(packet, packetPosition, packetPosition+2));
		packetPosition+=2;
		
		headerSize += packetPosition;	
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	
	/**
	 * This Method creates the part the first and subsequent header have in common
	 * 
	 * @param packet
	 * @return
	 */
	private byte[] createCorporateFragmentationHeader(byte[] packet){
		int packetPosition = 0;
		byte actualByte = packet[packetPosition];
		
		//get the datagramSize
		int maskedByte = (actualByte&(byte)7) & 0xFF;
		datagramSize = (maskedByte << 8) + (packet[packetPosition+1] & 0xFF);
		packetPosition+=2;
		
		//get the datagramTag
		datagramTag = byteArrayToInt(2,Arrays.copyOfRange(packet, packetPosition, packetPosition+2));
		packetPosition+=2;
		
		headerSize += packetPosition;	
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	

	private byte[] createIPHCHeader(byte[] packet){
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
		
		
		//TODO: everything else than FlowLabel (nh, hlim, cid, sac, sam, m, dac, dam
	
		
		headerSize += packetPosition;
		return Arrays.copyOfRange(packet, packetPosition, packet.length);
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
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

	public long getOriginatorAddress() {
		return originatorAddress;
	}

	public long getFinalAddress() {
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
