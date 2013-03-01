package packettracking.view;

import java.io.*;
import java.util.ArrayList;

import packettracking.controller.MainController;
import packettracking.model.MultihopPacketTrace;

/**
 * The MainViewCLI is the command line interface from MainController for additional requests to the results
 * of the TraceAnalyzer.
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-28  
 */
public class MainViewCLI {

	//declaring global variables
	//ctrl is needed for accessing the traces in the MainController
	MainController ctrl;
	//sign set by the user to exit MainViewCLI
	boolean exit;
	//options with help-information
	ArrayList<MainViewCLIOption> options;
	//last collection of results are saved for printing to file option
	ArrayList<MultihopPacketTrace> lastResults = null;
	
	/**
	 * The MainViewCLI needs the controller instance as variable to communicate 
	 * and also creates all MainViewCLIOptions on startup.
	 * 
	 * @param ctrl the MainController
	 */
	public MainViewCLI(MainController ctrl){
		this.ctrl = ctrl;
		//create a list with all options for the help-text
		options = new ArrayList<MainViewCLIOption>();
		options.add(new MainViewCLIOption("-help",null,"shows all possible commands"));
		options.add(new MainViewCLIOption("-traceByNode",new String[]{"nodeAddress"},"displays all traces initiated by the specified nodes MAC Address"));
		options.add(new MainViewCLIOption("-traceBetweenNodes",new String[]{"nodeAddress","nodeAddress"},"displays all traces between the specified nodes MAC Addresses (bi-directional)"));
		options.add(new MainViewCLIOption("-traceByFlowLabel",new String[]{"flowlabel"},"displays all traces inheriting the specified flow label"));
		options.add(new MainViewCLIOption("-unfinishedTransmissions",null,"lists all traces of transmissions which haven't reached the destination"));
		options.add(new MainViewCLIOption("-finishedTransmissions",new String[]{"broadcast"},"lists all traces of transmissions which have reached the destination (with/without broadcasts)"));
		options.add(new MainViewCLIOption("-printLastResults",new String[]{"file"},"prints the last results as a String to the specified textfile"));		
		options.add(new MainViewCLIOption("-exit",null,"quits the CLI"));
	}

	/**
	 * runCLI starts the CLI-loop
	 */
	public void runCLI(){
		//initial information
		System.out.println("Type in your command.");
		System.out.println("Write -help for a list of available commands.");
	
		//create an input reader
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String input = null;

		//run CLI-loop while no exit-command is read
		exit = false;
		while(!exit){
			//try to read command
	    	try {
	    		input = br.readLine();
	    	} catch (IOException ioe) {
	    		//command was illegal
	     		System.out.println("IO error trying to read your command!");
	     		System.exit(1);
	    	}
	    	//get results for command
	    	checkInput(input);
		}
		//close the reader after user enters "-exit" command
		try {
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * checkInput reads the users input to call the right method.
	 * Most of the time the MainController is used to calculate or filter the results. 
	 * 
	 * @param input String set by user
	 */
	private void checkInput(String input){
		//shows all possible commands
		if(input.startsWith("-help")){
			System.out.println("A list of all available commands:");
			for(MainViewCLIOption o : options){
				System.out.println(o.toString());
			}
		} 
		//displays all traces initiated by the specified nodes MAC Address
		else if(input.startsWith("-traceByNode")){
			try{
			String value = input.split(" ")[1];
				if(value != null){
					ArrayList<MultihopPacketTrace> results = ctrl.traceByNode(value);
					displayTraces(results);
				}
			} catch(Exception e){
				System.out.println("wrong input, example: -traceByNode 5678");
			}
		} 
		//displays all traces between the specified nodes MAC Addresses (bi-directional)
		else if(input.startsWith("-traceBetweenNodes")){
			try{
				String value = input.split(" ")[1];
				String value2 = input.split(" ")[2];
				if(value != null){
					ArrayList<MultihopPacketTrace> results = ctrl.traceBetweenNodes(value,value2);
					displayTraces(results);
				}
			} catch(Exception e){
				System.out.println("wrong input, example: -traceBetweenNodes 5678 9abc");
			}
		} 
		//displays all traces inheriting the specified flow label
		else if(input.startsWith("-traceByFlowLabel")){
			try{
				String value = input.split(" ")[1];
				if(value != null){
					ArrayList<MultihopPacketTrace> results = ctrl.traceByFlowLabel(value);
					displayTraces(results);
				}
			} catch(Exception e){
				System.out.println("wrong input, example: -traceByFlowLabel 32412");
			}
		}
		//lists all traces of transmissions which haven't reached the destination
		else if(input.startsWith("-unfinishedTransmissions")){
			System.out.println("A list of all unfinished transmissions:");
			ArrayList<MultihopPacketTrace> results = ctrl.unfinishedTraces();
			displayTraces(results);
		} 
		//lists all traces of transmissions which have reached the destination (with/without broadcasts)
		else if(input.startsWith("-finishedTransmissions")){
			try{
				String value = input.split(" ")[1];
				if(value != null){
					ArrayList<MultihopPacketTrace> results = ctrl.finishedTraces(Boolean.parseBoolean(value));
					System.out.println("A list of all finished transmissions:");
					displayTraces(results);
				}
			} catch(Exception e){
				System.out.println("wrong input, example: -finishedTransmissions false");
			}
		} 
		//prints the last results as a String to the specified textfile
		else if(input.startsWith("-printLastResults")){
			if(lastResults != null){
				try{
					String value = input.split(" ")[1];
					if(value != null){
						printLastResult(value);
					}
				} catch(Exception e){
					System.out.println("wrong input, example: -printLastResults output.txt");
				}
			} else {
				System.out.println("No results to print!");
			}
		} 
		//quits the CLI
		else if(input.startsWith("-exit")){
			exit = true;
		} 
		//... command used is unknown
		else {
			System.out.println("Unknown commaned used.");
		}
	}
	
	/**
	 * displayTraces runs the output of results for the user.
	 * 
	 * @param traces the traces to be displayed
	 */
	public void displayTraces(ArrayList<MultihopPacketTrace> traces){
		int counter = 1;
		//iterate through all traces to display them
		for(MultihopPacketTrace t : traces){
			System.out.println("Displaying Packet Trace #"+counter+": ");
			System.out.println(t.toString());
			counter++;
		}
		lastResults = traces;
		System.out.println("//////////////////////////////////////////\n");
	}
	  
	/**
	 * The method printLastResult prints an exact copy of the last results
	 * to an user specified file.
	 * 
	 * @param filename name of file to save
	 */
	public void printLastResult(String filename){
		BufferedWriter out;
		try {
			out = new BufferedWriter(new FileWriter(filename));
			System.out.println("Last results are printed to "+filename +"!");
			int counter = 1;
			for(MultihopPacketTrace t : lastResults){
				out.write("Displaying Packet Trace #"+counter+": ");
				out.write(t.toString());
				counter++;
			}
		} catch (Exception e) {
			System.out.println("Results cannot be printed to the specified file.");
		}
	}
}  