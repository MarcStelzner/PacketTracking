package packettracking.view;

import java.awt.FileDialog;
import java.awt.Frame;
import java.io.FileOutputStream;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

public class EncoderView {
	
	public EncoderView(){	
	}
	
	public boolean askForExport(){
		JFrame frame = new JFrame("The Question for export");		
		Object[] options = {"Yes", "No"};
		int n = JOptionPane.showOptionDialog(frame,
		"Do you want to export the logged data to .pcap?",
		"Export",
		JOptionPane.YES_NO_OPTION,
		JOptionPane.QUESTION_MESSAGE,
		null,     //do not use a custom Icon
		options,  //the titles of buttons
		options[0]); //default button title
	
		if(n == 0){
			return true;
		}
		else {
			return false;
		}
	}
	
	public void exportDataToFile(byte[] outputArray){
		System.out.println("All Packets ready to be saved.");
		
		//Open Dialog to save file
		FileDialog fd = new FileDialog(new Frame(), "Choose file to save converted Datalog.", FileDialog.SAVE);
		fd.setFile("output.pcap");
	    fd.setDirectory(".\\");
	    fd.setLocation(50, 50);
	    fd.setVisible(true);
	    
	    
	    //Check for existence of the given address
	    if(!(fd.getFile() == null)){
	    	String address = fd.getDirectory() + fd.getFile();//System.getProperty("file.separator") + fd.getFile();
	    	//check ending of file (to be .pcap), otherwise fix it
		    if(!address.endsWith(".pcap")){
		    	address += ".pcap";
		    }
		    
			System.out.println("Writing to file "+ address + " ...");

			//try to save at given address
			try{
				FileOutputStream output = new FileOutputStream(address);
				output.write(outputArray);
				fd.dispose();
				System.out.println("Data to "+ address + " is succesfully saved.");
				System.out.println("Work done, terminating ...");
			} catch(Exception e){
				System.out.print("Error on saving: " + e);
			}
	    } 
	    // Address given is impossible to save at ? --> terminate 
	    else {
	    	System.out.print("Invalid storing-address, terminating ...");
	    }
	}
}
