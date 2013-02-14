package packettracking;

import packettracking.controller.MainController;

public class Main {
	public static void main(String[] args) {
		MainController coordinator = new MainController(); 
		boolean testRun = true;
		int timeBetweenTraces = 3;
		for(String arg : args){
			//run with testdata ?
			if(arg.equals("testrun")){
				testRun = true;
			}
			//look for a number for setting timeBetweenTraces
			else{
				try{
					timeBetweenTraces = Integer.parseInt(arg);			
				} catch(NumberFormatException e){
					//was no number
				}
			}
		}
		coordinator.run(testRun, timeBetweenTraces);
	}
}
