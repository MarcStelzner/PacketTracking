package packettracking;

import packettracking.controller.Controller;

public class Main {
	public static void main(String[] args) {
		Controller coordinator = new Controller(); 
		boolean testRun = false;
		coordinator.run(testRun);
	}
}
