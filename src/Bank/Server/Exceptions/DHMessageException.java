package Bank.Server.Exceptions;

public class DHMessageException extends Exception {
	
	public DHMessageException() {
		super("That's not a DH message");
	}
}
