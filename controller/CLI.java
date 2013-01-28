package packettracking.controller;

import java.io.*;
import java.util.ArrayList;

import packettracking.model.MultihopPacketTrace;

public class CLI {

	Controller ctrl;
	boolean exit;
	ArrayList<CLIOption> options;
	
	public CLI(Controller ctrl){
		this.ctrl = ctrl;
		options = new ArrayList<CLIOption>();
		options.add(new CLIOption("-help",null,"shows all possible commands"));
		options.add(new CLIOption("-traceByNode",new String[]{"nodeAddress"},"displays all traces initiated by the specified nodes MAC Address"));
		options.add(new CLIOption("-traceBetweenNodes",new String[]{"nodeAddress","nodeAddress"},"displays all traces between the specified nodes MAC Addresses (bi-directional)"));
		options.add(new CLIOption("-traceByFlowLabel",new String[]{"flowlabel"},"displays all traces inheriting the specified flow label"));
		options.add(new CLIOption("-exit",null,"quits the CLI"));
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
			for(CLIOption o : options){
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
		} else if(input.startsWith("-exit")){
			exit = true;
		} 
	}
	
	public void displayTraces(ArrayList<MultihopPacketTrace> traces){
		int counter = 1;
		for(MultihopPacketTrace t : traces){
			System.out.println("Displaying Packet Trace #"+counter+": ");
			System.out.println(t.toString());
			counter++;
		}
		System.out.println("//////////////////////////////////////////\n");
	}
	   
}  