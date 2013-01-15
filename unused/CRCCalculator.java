package packettracking.unused;

public class CRCCalculator {
	
	
	
	public static byte[] makeCRC(byte[] toCalculate){
		
	   //static char Res[17];                                 // CRC Result
//	   char CRC[16];  
//	   char DoInvert;
	   
	   byte[] crc = new byte[2];
	   crc[0] = 0;
	   crc[1] = 0;
	   
	   
// 	   for (int i=0; i<16; ++i)  CRC[i] = 0;                    // Init before calculation
	   
	   //jedes byte
	   for (int i=0; i<toCalculate.length; ++i)
	   {
		   //jedes bit
		   for(int j = 0; j<8 ; j++)
		   {
			   boolean invert = false;
			   //TODO: hier j drehen, falls bytes andersherum lesen
			   //falls ENTWEDER das zu berechnende bit oder crc (pos 15) 1 sind, dann invert = 1
			   if(((toCalculate[i] & (0x01<<(7-j))) ^ (crc[1]&0x01)) > 0){
				   invert = true;
			   }
			   
			   //high-byte shiften
			   crc[1] = (byte)(crc[1] >> 1);
			   //carry hinzufügen, falls nötig
			   if((crc[0] & 0x01) > 0){
				   crc[1] = (byte)(crc[1] | 0x80);
			   }
			   //low-byte shiften
			   crc[0] = (byte)(crc[0] >> 1);
			   //nun drei spezifische inverse durchführen, passend zum CRC (12,5,0) -> (crc[0]:0,5 und crc[1]:4)
			   //---> 0 x 1 
			   if (invert){
				   crc[0] ^= 1 << 7;
				   crc[0] ^= 1 << 2;
				   crc[1] ^= 1 << 3;
			   }
			   /*
			   
			   //bitmasken durch &-Operator erreichen
	      DoInvert = ('1'==BitString[i]) ^ CRC[15];         // XOR required?
	      //--> if Bitstring i is 1 or CRC[15] is true ---> DoInvert = 1

	      CRC[15] = CRC[14];   int k = (crc[1]&0x02);
	      CRC[14] = CRC[13];
	      CRC[13] = CRC[12];
	      CRC[12] = CRC[11] ^ DoInvert;
	      CRC[11] = CRC[10];
	      CRC[10] = CRC[9];
	      CRC[9] = CRC[8];
	      CRC[8] = CRC[7];
	      CRC[7] = CRC[6];
	      CRC[6] = CRC[5];
	      CRC[5] = CRC[4] ^ DoInvert;
	      CRC[4] = CRC[3];
	      CRC[3] = CRC[2];
	      CRC[2] = CRC[1];
	      CRC[1] = CRC[0];
	      CRC[0] = DoInvert;*/
	      }
	   }
	   return crc;
	}

}
