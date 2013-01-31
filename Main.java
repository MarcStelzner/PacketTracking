package packettracking;

import packettracking.controller.MainController;

public class Main {
	public static void main(String[] args) {
		MainController coordinator = new MainController(); 
		boolean testRun = false;
		coordinator.run(testRun);
	}
}
