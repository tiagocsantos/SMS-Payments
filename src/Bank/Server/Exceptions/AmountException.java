package Bank.Server.Exceptions;

public class AmountException extends Exception {

	public AmountException(String message) {
		super("Amount " + message + " is incorrect");
	}

}
