package packettracking.view;

import java.awt.FileDialog;
import java.awt.Frame;

import javax.swing.JFrame;
import javax.swing.JOptionPane;

/**
 * DecoderView is the interface for the Decoder for input/output of the data
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-02-14  
 */
public class DecoderView {

	public DecoderView(){
	}
	
	/**
	 * The method opens a dialog with the user and asks for used protocols.
	 * 
	 * @return true if a protocol was used
	 */
	public boolean askForProtocols(){
		//Ask user if any protocol (only 6lowpan is supported at the moment) was used or just plain data
		JFrame frame = new JFrame("The Question for protocols");		
		Object[] options = {"Plain Payload", "Protocols"};
		int n = JOptionPane.showOptionDialog(frame,
		"To avoid false protocol detection:\n" +
		"Are any standardized protocols used in the datalog or was just plain payload used?\n" +
		"(Only 6LoWPAN is supported in this version)",
		"Protocols",
		JOptionPane.YES_NO_OPTION,
		JOptionPane.QUESTION_MESSAGE,
		null,     //do not use a custom Icon
		options,  //the titles of buttons
		options[0]); //default button title
		
		//the information is used to recognize additional payload-data
		if(n == 1){
			return true;
		}
		else {
			return false;
		}
	}
	
	/**
	 * The method opens a dialog with the user and asks for the destination where the logs to read are saved
	 * 
	 * @return FileDialog gets returned to the Decoder, to read answer
	 */
	public FileDialog askForDestination(){
		//Dialog to load Data
	    FileDialog fd = new FileDialog(new Frame(), "Choose the Datalog \"*.txt\" to read.", FileDialog.LOAD);
	    fd.setFile("*.txt");
	    fd.setDirectory(".\\");
	    fd.setLocation(50, 50);
	    fd.setVisible(true);
		//get address out of dialog
	    return fd;
	}
	
}
