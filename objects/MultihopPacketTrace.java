package packettracking.objects;

import java.util.ArrayList;
import java.util.UUID;

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
	private int firstTimeMicroseconds;
	private int lastTime;
	private int lastTimeMicroseconds;
	
	//TODO: maybe useful as a reference
	private final UUID uuid;
	
	//TODO: which ones of the three are useful ? ---> or other plan to build a path ?
	private Node source;
	private Node[] intermediateNodes; // the nodes between the source and the destinations
	private Node[] destination; //plural, because of (broadcasts, multicasts)

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
		firstTimeMicroseconds = -1;
		lastTime = -1; 
		lastTimeMicroseconds = -1;
		
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
		firstTimeMicroseconds = -1;
		lastTime = -1; 
		lastTimeMicroseconds = -1;
		
		uuid  = UUID.randomUUID();
	}
	
	public int getFlowLabelOccurence() {
		return flowLabelOccurence;
	}

	public int getFlowLabel() {
		return flowLabel;
	}

	public int getFirstTime() {
		return firstTime;
	}
	
	public int getFirstTimeMicroseconds() {
		return firstTimeMicroseconds;
	}

	public int getLastTime() {
		return lastTime;
	}
	
	public int getLastTimeMicroseconds() {
		return lastTimeMicroseconds;
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
		int packetSeconds = byteArrayToInt(4, packet.getSeconds());
		int packetMicroSeconds = byteArrayToInt(4, packet.getMicroSeconds());
		
		//if there is no first time or the new first Time is earlier, than renew it
		if(firstTime < 0 || firstTime > packetSeconds 
				|| ((firstTime == packetSeconds)&&(firstTimeMicroseconds > packetMicroSeconds))){
			firstTime = packetSeconds;
			firstTimeMicroseconds = packetMicroSeconds;
		}
		
		//if there is no last time or the new first Time is earlier, than renew it
		if(lastTime < packetSeconds 
				|| ((lastTime == packetSeconds)&&(lastTime < packetMicroSeconds))){
			lastTime = packetSeconds;
			lastTimeMicroseconds = packetMicroSeconds;
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
}
