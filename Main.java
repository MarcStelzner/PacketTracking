package packettracking;

import packettracking.controller.MainController;

/**
 * Main class for the packettracking analyzer
 * 
 * @author 		Marc
 * @version     1.0                 
 * @since       2013-01-15          
 */
public class Main {
	public static void main(String[] args) {
		MainController coordinator = new MainController(); 
		//set default values for the application
		boolean testRun = false;
		int timeBetweenTraces = 3;
		//check for existing args
		for(String arg : args){
			//run with testdata ?
			if(arg.equals("testrun")){
				testRun = true;
			}
			//look for a number for setting timeBetweenTraces
			else{
				try{
					int tmpTime = Integer.parseInt(arg);
					if(tmpTime > 0){
						timeBetweenTraces = tmpTime;
					}		
				} catch(NumberFormatException e){
					//value was no number
				}
			}
		}
		//start the core of the analyzer
		coordinator.run(testRun, timeBetweenTraces);
	}
}
