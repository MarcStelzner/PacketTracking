package packettracking.view;

/**
 * The MainViewCLIOption has only the use of beeing an information output in
 * the MainViewVLI, describing the possible commands, which shall be implemented similar.
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-28  
 */
public class MainViewCLIOption {
	
	String command;
	String[] args;
	String helpText;
	int maxCommandLength = 50;
	
	/**
	 * The constructor must get all information about the option
	 * 
	 * @param command the main command-type
	 * @param args the arguments to the command
	 * @param helpText additional information about the command
	 */
	public MainViewCLIOption(String command, String args[], String helpText){
		this.command = command;
		if(args == null){
			this.args = new String[0];
		} else {
			this.args = args;
		}
		this.helpText = helpText;
	}
	
	/**
	 * Printing out information about the option
	 * 
	 * @return formatted String
	 */
	@Override
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
