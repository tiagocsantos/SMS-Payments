package Bank.Server;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Encoder;
import Bank.Server.Exceptions.AmountException;
import Bank.Server.Exceptions.DHMessageException;
import Bank.Server.Exceptions.DataSizeException;
import Bank.Server.Exceptions.IbanException;
import sun.misc.BASE64Encoder;

public class Message {
	
	private static byte[] Confirmation_Ack = 	new byte[] {0,0};	//transfer completed
	private static byte[] Amount_Error_Ack = 	new byte[] {1,1};	//amount not available 
	private static byte[] Source_Unknown_Ack = new byte[] {1,0};		//source iban not found
	private static byte[] Dest_Unknown_Ack = 	new byte[] {0,1};	//dest iban not fount
	private static byte[] Not_Autorized_Ack = new byte[] {2,0};		//source iban doesnt belong to that port
	
	private long ID;
	private String type;
	private String data;
	private String key = null;
	
	private static SecureRandom randomizer = new SecureRandom(); 

	//request port to server
	public Message(){
		this.ID =  new BigInteger(64, randomizer).abs().longValue();
		this.type = "request";
		this.data = "";
	}
	
	
	//response to request port
	public Message(int port) {
		this.ID =  new BigInteger(64, randomizer).longValue();
		this.type = "port";
		setPort(port);
	}

	//message to distribute keys
	public Message(String p){
		this.type = null;
		setPublicKeys(p);
	}
	
	//Association command
	public Message(String iban, int number) throws IbanException, DataSizeException{ 
		this.ID =  new BigInteger(64, randomizer).abs().longValue();
		this.type = "associate";
		setIban(iban);
		setPhone(number);
	}
	

	//Send command
	public Message(String iban, String amount, int number) throws IbanException, AmountException, DataSizeException{
		this.ID =  new BigInteger(64, randomizer).abs().longValue();
		this.type = "send";
		setIban(iban);
		setAmount(amount);
		setPhone(number);
	}
	
	
	//Client send code of matrix card
	public Message(char[] code){
		this.ID =  new BigInteger(64, randomizer).abs().longValue();
		this.type = "codes_answer";
		this.data = new String(code);
	}
	
	
	//Acknowledge message
	public Message(byte[] ack){
		this.type = "ack";
		setAck(ack);
	}
	
	// Iv message
	public Message(byte[] iv, boolean t){
		ID = new BigInteger(64, randomizer).abs().longValue();
		type = "iv_share";
		data = new String(iv);
	}
	
	//Server sends positions of matrix card
	public Message(int[] a, int[] b, int[] c, int[] d){
		this.ID =  new BigInteger(64, randomizer).longValue();
		this.type = "codes";
		setCodes(a,b,c,d);
	}

	private void setCodes(int[] a, int[] b, int[] c, int[] d) {
		String line = ":column_" + (a[0]+1) + "_line_" + (a[1]+1) + ":";
		line += "column_" + (b[0]+1) + "_line_" + (b[1]+1) + ":";
		line += "column_" + (c[0]+1) + "_line_" + (c[1]+1) + ":";
		line += "column_" + (d[0]+1) + "_line_" + (d[1]+1) + ":";
		this.data = line;
	}
	
	private byte[] getDigest() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException{
		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(),"HmacSHA256");
		Mac m = Mac.getInstance("HmacSHA256");
		m.init(keySpec);
		byte[] hash = m.doFinal(this.getAll());
		byte[] small = new byte[8];
		small = Arrays.copyOfRange(hash, 0, 8);
		return small;
	}
	
	public void setKey(String sessionKey){
		this.key = sessionKey;
	}
	
	private byte[] getAll() {
		return this.getMessage().getBytes();
	}


	private void setAck(byte[] ack) {
		if(Arrays.equals(ack, Confirmation_Ack)){
			this.data = "confirmed";
		}else if(Arrays.equals(ack, Amount_Error_Ack)){
			this.data = "amount_error";
		}else if(Arrays.equals(ack, Dest_Unknown_Ack)){
			this.data = "destination_unknown";
		}else if(Arrays.equals(ack, Source_Unknown_Ack)){
			this.data = "source_unknown";
		}else if(Arrays.equals(ack, Not_Autorized_Ack)){
			this.data = "not_authorized";
		}
	}
	
	private void setPublicKeys(String p){
		this.data = p;
	}
	
	private void setPort(int port) {
		this.data = "" + port;
	}

	private void setIban(String iban) throws IbanException, DataSizeException{
		if(verifyIban(iban)){
			setData(iban);
		}
		else{
			throw new IbanException(iban);
		}
	}
	
	private void setPhone(int number) throws DataSizeException {
		String aux;
		aux = this.data;
		aux += " "+number;
		setData(aux);
	}
	
	private void setAmount(String amount) throws AmountException, DataSizeException{
		
		String aux;
		
		if(verifyAmount(amount)){
			aux = this.data;
			aux += " " + amount;
			setData(aux);
		}
		else{
			throw new AmountException(amount);
		}
	}
	
	private void setData(String data) throws DataSizeException{
		if(data.length()>72)
			throw new DataSizeException();
		else{
			this.data = data;
		}
	}
	
	private boolean verifyIban(String iban){
		if(iban.length() == 25){
			String letters = iban.substring(0, 1);
			String numbers = iban.substring(2,iban.length());
			if(letters.matches("[A-Z]+") && numbers.matches("[0-9]+"))
				return true;
		}
		return false;
	}
	
	private boolean verifyAmount(String amount){
		long value = Long.parseLong(amount);
		if(value > 0 && amount.length()<=8)
			return true;
		return false;
	}
	
	protected void setID(long id){
		this.ID = id;
	}
	
	public long getID(){
		return this.ID;
	}
	
	private String getType(){
		return this.type;
	}
	
	public String getData(){
		return this.data;
	}
	
	
	private String getMessage(){
		return getType() + "||" + getID() + "||" + getData() +"||";
	}
	
	public String getDHMessage() throws DHMessageException{
		if(getType()==null)
			return getData();
		throw new DHMessageException();
	}
	
	public byte[] getMessageBytes() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException{
		byte[] message = new byte[getMessage().getBytes().length+getDigest().length];
		System.arraycopy(getMessage().getBytes(), 0, message, 0, getMessage().getBytes().length);
		System.arraycopy(getDigest(), 0, message, getMessage().getBytes().length, getDigest().length);
		return message;
	}
}
