package Bank.Client;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import Bank.Server.AES;
import Bank.Server.Message;
import Bank.Server.Exceptions.*;


public class Client {
	private static final int ServerPort = 10100;
	private static final String ServerHost = "localhost";
	
	private static InetAddress addr; 
	private static DatagramSocket socket;
	private static int port;
	private static Scanner in;
	private static int phone_number;
	
	private static SecureRandom randomizer = new SecureRandom();
	
	private static BigInteger b = new BigInteger(10, randomizer);
	private static String sessionKey;
	
	private static AES cbc;
	
	public static void main(String[] args) throws Exception {
		
		addr = InetAddress.getByName(ServerHost);
		socket = new DatagramSocket();
		requestPort();
		
		generateDHPublicValues();
		generateDHSecretKey();
		
		cbc = new AES(sessionKey);
		
		System.out.println("Client started running...");
		
		in = new Scanner(System.in);
		
		setPhoneNumber();
		System.out.println("Client started running...");
		for(String input = in.nextLine(); !(input.toLowerCase().equals("exit")); input = in.nextLine()){
			if(input.toLowerCase().startsWith("send ")){
				try {
					String writtenCommand = input.substring(input.indexOf(" ")+1, input.length());
					
					sendEncryptedMessage(writtenCommand);
				
				} catch (Exception e) {
					System.out.println(e.getMessage());
				}
			}
			else if(input.toLowerCase().startsWith("associate ")){
				String writtenCommand = input.substring(input.indexOf(" ")+1, input.length());
				try {
					associateCommand(writtenCommand);
				} catch (Exception e) {
					e.printStackTrace();
					System.out.println(e.getMessage());
				}
			}
			else {
				System.out.println("Comando desconhecido");
				System.out.println("Comandos disponiveis: SEND\tASSOCIATE");
			}
		}
		in.close();
	}
	
	private static void requestPort() throws IOException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		Message m = new Message();
		m.setKey("none");
		byte[] msgBytes = m.getMessageBytes();
		DatagramPacket packet = new DatagramPacket(msgBytes,msgBytes.length, addr, ServerPort);
		
		socket.send(packet);
		
		byte[] ack = new byte[120];
        DatagramPacket ackpacket = new DatagramPacket(ack, ack.length);
        
        socket.receive(ackpacket);
		
        String content[] = new String(ackpacket.getData()).split("\\|\\|");
        System.out.println(content[2]);
        String nr_port = content[2].substring(0, 5);
        if(content[0].equals("port")){
        	port = Integer.parseInt(nr_port);
        	System.out.println("Joined at port " + port);
        }
        else System.exit(-1);
		
	}

	public static void setPhoneNumber(){

		String input = new String();
		
		System.out.println("Insert the phone number that you pretend associate to your account");
		
		while(true){
			input = in.nextLine();
			
			if(input.matches("[0-9]+") && input.length() == 9){
				phone_number = Integer.parseInt(input);
				break;
			}else{
				System.out.println("The number is invalid, it should have 9 digits");
			}
		}
	}
	
	private static void generateDHPublicValues() throws Exception{
				
		BigInteger p = new BigInteger(10, randomizer);
		BigInteger q = new BigInteger(10, randomizer);
		BigInteger yB = new BigInteger(10, randomizer);
		
		int bitLength = 512; // 1024 bits
	    
	    p = BigInteger.probablePrime(bitLength, randomizer);
	    //System.out.println("p: "+p.longValue());
	    
	    q = BigInteger.probablePrime(bitLength, randomizer);
	    //System.out.println("q: "+q.longValue());
	    
	    b = BigInteger.probablePrime(bitLength, randomizer);
	    
	    yB = p.modPow(b, q);
	    //System.out.println("yB: "+yB.longValue());
	    
	    byte[] messages = p.toByteArray();
	    sendDHMessage(messages);
	    
	    messages = q.toByteArray();
	    sendDHMessage(messages);
	    
	    messages = yB.toByteArray();
	    sendDHMessage(messages);
	    
	}
	
	private static void sendDHMessage(byte[] byteList) throws IOException, DHMessageException{
		
		DatagramPacket keysPacket = new DatagramPacket(byteList, byteList.length, addr, port);
		socket.send(keysPacket);
	}
	
	private static BigInteger collectDHValues() throws IOException{
		
		ByteArrayOutputStream aux = new ByteArrayOutputStream();
		
		byte[] keys = new byte[120];
		DatagramPacket keysPacket = new DatagramPacket(keys, keys.length); 
		socket.receive(keysPacket);
		
		aux.write(Arrays.copyOfRange(keysPacket.getData(), 0, keysPacket.getLength()));
		
		return new BigInteger(aux.toByteArray());
	}
	
	private static void generateDHSecretKey() throws IOException{
		
		BigInteger q = collectDHValues();
		//System.out.println("q recebido:" +q.longValue());
		
		BigInteger yA = collectDHValues();
		//System.out.println("yA recebido:" +yA.longValue());
		
		BigInteger resultado = yA.modPow(b, q);
		
		System.out.println("Chave Secreta: "+ resultado.longValue());
		
		sessionKey = new String(""+resultado);
		sessionKey = sessionKey.substring(0, 16);
		
		System.out.println("session key: "+sessionKey);
		
	}
	
	private static void associateCommand(String input) throws Exception{
		Message m = new Message(input, phone_number);
		sendEncryptedMessage(m);
	}
	
	private static void sendEncryptedMessage(String input) throws IbanException, AmountException, DataSizeException, InvalidKeyException, NumberFormatException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException{
		String info[] = input.split(" ");
		Message m = new Message(info[0], info[1], phone_number);
		sendEncryptedMessage(m);
	}
	
	private static void sendEncryptedMessage(Message m) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NumberFormatException, IOException, IbanException, AmountException, DataSizeException{
		
		m.setKey(sessionKey);
		
		if (!generateIV()){
			System.out.println("could not deliver iv");
			return;
		}
		System.out.println("IV SHARED");
		System.out.write(cbc.getIV());
		System.out.println();
		Long l = m.getID() - 2;
	
		byte[] cypherBytes = cbc.encrypt(new String(m.getMessageBytes()));
		
		DatagramPacket packet = new DatagramPacket(cypherBytes,cypherBytes.length, addr, port);
		
		sendPacket(packet, l);	
	}
	
	private static void sendNonEncryptedMessage(Message m) throws IbanException, AmountException, DataSizeException, InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		
		Long l = m.getID()-2;
		
		byte[] msgBytes = m.getMessageBytes(); //with digest
		
		DatagramPacket packet = new DatagramPacket(msgBytes,msgBytes.length, addr, port);
		
		sendPacket(packet, l);
	}
	
	private static void sendPacket(DatagramPacket packet, long id) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NumberFormatException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		socket.send(packet);
		System.out.println("Packet Sent");
		
		if(!waitAck(id)){
			System.out.println("Operation not completed.");
			return;
		}
		
		if(!confirmIdentity()){
			System.out.println("Identity not confirmed.");
			System.out.println("Operation not completed.");
			return;
		}
		
		System.out.println("Transaction completed with success");
		
	}
	
	private static boolean generateIV() throws InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException, IbanException, AmountException, DataSizeException, IOException{
		
		cbc.generateIV();
		
		DatagramPacket p = new DatagramPacket( cbc.getIV(), cbc.getIV().length, addr, port );
		socket.send(p);
		
		return true;

	}
	
	private static boolean waitAck(Long l) throws IOException, InvalidKeyException, NoSuchAlgorithmException {

		boolean ackReceived = false;
		boolean timeout = false;

		byte[] ack = new byte[120];
        DatagramPacket ackpacket = new DatagramPacket(ack, ack.length);

		while (!ackReceived && !timeout) {
			System.out.println("Sent message, waiting for ack");
			
			try {
				socket.setSoTimeout(4000);
				socket.receive(ackpacket);
				
				byte[] received = Arrays.copyOf(ackpacket.getData(), ackpacket.getLength());
				
				String content[] = new String(received).split("\\|\\|");
				
			//	if(!validateDigest(received)){
				//	return false;
				//}
				
				if(content[0].equals("ack")){
					String client_info = "";
					if(Long.parseLong(content[1]) != l){
						client_info = "Operation not authorized";
						return false;
					}
					System.out.println("Acknowlegde received");
					ackReceived = true;
					if(content[2].equals("confirmed")){
						return true;
						
					}else if(content[2].equals("amount_error")){
						client_info = "The amount entered is higher than the current balance.";
					}else if(content[2].equals("destination_unknown")){
						client_info = "The IBAN entered is not registered.";
					}else if(content[2].equals("source_unknown")){
						client_info = "The IBAN entered is not registered.(Source)";
					}else if(content[2].equals("not_authorized")){
						client_info = "Operation not authorized";
					}
					System.out.println(client_info);
				}
			}
			catch (SocketTimeoutException e){
				System.out.println("timeout expired");
				ackReceived = false;
				timeout = true;
			}
		}
		return false;
	}
	
	private static boolean confirmIdentity() throws IOException, NoSuchAlgorithmException, NumberFormatException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		
		byte[] codes = new byte[120];
		DatagramPacket codePacket = new DatagramPacket(codes, codes.length);
		try {
			socket.setSoTimeout(10000);
			socket.receive(codePacket);
			//socket.setSoTimeout(0);
			
				
		} catch (SocketTimeoutException e) {
			System.out.println("Server did not send confirmation in time.");
			System.out.println("Operation canceled");
			return false;
		}
		byte[] received = Arrays.copyOf(codePacket.getData(), codePacket.getLength());
		String content[] = new String(received).split("\\|\\|");
		System.out.println(new String(received));
		if(!content[0].equals("codes")){
			return false;
		}
		//if(!validateDigest(received)){
	//		return false;
		//}	
		
		System.out.println(content[2]);
		Scanner in2 = new Scanner(System.in);
		String input = in2.nextLine();
		char[] code = input.toCharArray();
		Message m = new Message(code);
		m.setKey(sessionKey);
		
		in = in2;
		
		byte[] answer = cbc.encrypt(new String(m.getMessageBytes()));
		
		DatagramPacket answerPacket = new DatagramPacket(answer, answer.length, addr, port);
		socket.send(answerPacket);
		
		Long l = Long.parseLong(new String(m.getMessageBytes()).split("\\|\\|")[1])-2;
		
		if(!waitAck(l)){
			System.out.println("Operation not completed.");
			return false;
		}
		
		return true;
	}
	
	private static boolean validateDigest(byte[] msg) throws NoSuchAlgorithmException, InvalidKeyException{
		int index = new String(msg).lastIndexOf('|');
		byte[] original =Arrays.copyOfRange(msg, index+1, msg.length);
		byte[] received = calculateDigest(new String(msg).substring(0, index+1));
		if(Arrays.equals(original, received)){
			return true;
		}
		return false;
	}
	
	private static byte[] calculateDigest(String msg) throws NoSuchAlgorithmException, InvalidKeyException{
		SecretKeySpec keySpec = new SecretKeySpec(sessionKey.getBytes(),"HmacSHA256");
		Mac m = Mac.getInstance("HmacSHA256");
		m.init(keySpec);
		byte[] hash = m.doFinal(msg.getBytes());
		byte[] small = new byte[8];
		small = Arrays.copyOfRange(hash, 0, 8);
		return small;
	}
	
}
