package Bank.Server.Exceptions;

public class DataSizeException extends Exception{
	
	public DataSizeException() {
		super("Data exceeds 72 chars");
	}
}
