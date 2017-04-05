package Bank.Server.Exceptions;

public class IbanException extends Exception {


	public IbanException(String msg) {
		super("Iban "+ msg + " is incorrect");
	}

}
