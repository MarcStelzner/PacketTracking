package packettracking.view;

import java.io.*;
import java.util.ArrayList;

import packettracking.controller.MainController;
import packettracking.model.MultihopPacketTrace;

public class MainViewCLI {

	MainController ctrl;
	boolean exit;
	ArrayList<MainViewCLIOption> options;
	ArrayList<MultihopPacketTrace> lastResults = null;
	
	public MainViewCLI(MainController ctrl){
		this.ctrl = ctrl;
		options = new ArrayList<MainViewCLIOption>();
		options.add(new MainViewCLIOption("-help",null,"shows all possible commands"));
		options.add(new MainViewCLIOption("-traceByNode",new String[]{"nodeAddress"},"displays all traces initiated by the specified nodes MAC Address"));
		options.add(new MainViewCLIOption("-traceBetweenNodes",new String[]{"nodeAddress","nodeAddress"},"displays all traces between the specified nodes MAC Addresses (bi-directional)"));
		options.add(new MainViewCLIOption("-traceByFlowLabel",new String[]{"flowlabel"},"displays all traces inheriting the specified flow label"));
		options.add(new MainViewCLIOption("-unfinishedTransmissions",null,"lists all traces of transmissions which haven't reached the destination"));
		options.add(new MainViewCLIOption("-finishedTransmissions",null,"lists all traces of transmissions which have reached the destination"));
		options.add(new MainViewCLIOption("-printLastResults",new String[]{"file"},"prints the last results as a String to the specified textfile"));		
		options.add(new MainViewCLIOption("-exit",null,"quits the CLI"));
	}

	public void runCLI(){
		System.out.println("Type in your command.");
		System.out.println("Write -help for a list of available commands.");
	
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	
		String input = null;
	
		exit = false;
		while(!exit){
	    	try {
	    		input = br.readLine();
	    	} catch (IOException ioe) {
	     		System.out.println("IO error trying to read your command!");
	     		System.exit(1);
	    	}
	    	checkInput(input);
		}
		try {
			br.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void checkInput(String input){
		if(input.startsWith("-help")){
			System.out.println("A list of all available commands:");
			for(MainViewCLIOption o : options){
				System.out.println(o.toString());
			}
		} else if(input.startsWith("-traceByNode")){
			try{
			String value = input.split(" ")[1];
				if(value != null){
					ArrayList<MultihopPacketTrace> results = ctrl.traceByNode(value);
					displayTraces(results);
				}
			} catch(Exception e){
				System.out.println("wrong input, example: -traceByNode 5678");
			}
		} else if(input.startsWith("-traceBetweenNodes")){
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
		} else if(input.startsWith("-traceByFlowLabel")){
			try{
				String value = input.split(" ")[1];
				if(value != null){
					ArrayList<MultihopPacketTrace> results = ctrl.traceByFlowLabel(value);
					displayTraces(results);
				}
			} catch(Exception e){
				System.out.println("wrong input, example: -traceByFlowLabel 32412");
			}
		} else if(input.startsWith("-unfinishedTransmissions")){
			System.out.println("A list of all unfinished transmissions:");
			ArrayList<MultihopPacketTrace> results = ctrl.unfinishedTraces();
			displayTraces(results);
		} else if(input.startsWith("-finishedTransmissions")){
			System.out.println("A list of all finished transmissions:");
			ArrayList<MultihopPacketTrace> results = ctrl.finishedTraces();
			displayTraces(results);
		} else if(input.startsWith("-printLastResults")){
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
		} else if(input.startsWith("-exit")){
			exit = true;
		} else {
			System.out.println("Unknown commaned used.");
		}
	}
	
	public void displayTraces(ArrayList<MultihopPacketTrace> traces){
		int counter = 1;
		for(MultihopPacketTrace t : traces){
			System.out.println("Displaying Packet Trace #"+counter+": ");
			System.out.println(t.toString());
			counter++;
		}
		lastResults = traces;
		System.out.println("//////////////////////////////////////////\n");
	}
	  
	public void printLastResult(String filename){
		//PrintWriter out;
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