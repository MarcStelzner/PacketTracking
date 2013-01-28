package packettracking.controller;

public class CLIOption {
	
	String command;
	String[] args;
	String helpText;
	int maxCommandLength = 50;
	
	public CLIOption(String command, String args[], String helpText){
		this.command = command;
		if(args == null){
			this.args = new String[0];
		} else {
			this.args = args;
		}
		this.helpText = helpText;
	}
	
	/**
	 * printing out information about the option
	 */
	public String toString(){
		String returnString = command;
		for(String arg : args){
			returnString += " <"+arg+">";
		}
		int length = returnString.length();
		if(length<maxCommandLength){
			for(int i = 0 ; i < (maxCommandLength-length); i++){
				returnString += " ";
			}
		}
		returnString +=	helpText;
		
		
		return returnString;
	}
}
