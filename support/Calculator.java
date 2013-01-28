package packettracking.support;

import java.math.BigInteger;
import java.util.Arrays;

public class Calculator {
	/**
	 * This Method turns bytearrays of a maximum length of 4 (byte) into integer
	 * 
	 * @param length
	 * @param array
	 * @return
	 */
	public static int byteArrayToInt(byte[] array){
		int newInt = 0;
		if(array.length > 4){
			System.out.println("Bytearray is too large with a size of "+array.length+". Only a length of 4 is possible (32 bit for int). Last "+(array.length-4)+" bytes will be ignored." );
			array = Arrays.copyOfRange(array, 0, 4);
		}
		for(int i = 0 ; i < array.length ; i++){
			newInt += ((array[i] & 0xFF) << ((array.length-1-i)*8));
		}
		return newInt;
	}
	
	/**
	 * This Method turns bytearrays of a maximum length of 8 (byte) into long
	 * 
	 * @param length
	 * @param array
	 * @return
	 */
	public static long byteArrayToLong(byte[] array){
		long newLong = 0;
		if(array.length > 8){
			System.out.println("Bytearray is too large with a size of "+array.length+". Only a length of 8 is possible (64 bit for long). Last "+(array.length-8)+" bytes will be ignored." );
			array = Arrays.copyOfRange(array, 0, 8);
		}
		for(int i = 0 ; i < array.length ; i++){
			newLong += ((array[i]& 0xFF) << ((array.length-1-i)*8));
		}
		return newLong;
	}
	
	/**
	 * This Method turns bytearrays of a maximum length of 8 into long
	 * 
	 * @param length
	 * @param array
	 * @return
	 */
	public static BigInteger byteArrayToBigInteger(byte[] array){
		BigInteger newBig = new BigInteger ("0");
		if(array.length > 16){
			System.out.println("Bytearray is too large with a size of "+array.length+". Only a length of 8 is possible (128 bit for BigInteger). Last "+(array.length-16)+" bytes will be ignored." );
			array = Arrays.copyOfRange(array, 0, 16);
		}
		for(int i = 0 ; i < array.length ; i++){
			newBig.shiftLeft(8);
			newBig.add(new BigInteger((array[i]& 0xFF)+""));		
		}
		return newBig;
	}
	
	
	public static String bytesToHex(byte[] bytes) {
	    final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	    char[] hexChars = new char[bytes.length * 2];
	    int v;
	    for ( int j = 0; j < bytes.length; j++ ) {
	        v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
}
