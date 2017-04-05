package Bank.Server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class MatrixCard {
	
	private static final String abc = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	private static SecureRandom rnd = new SecureRandom();
	private File f;

	MatrixCard(String name){
		this.f = new File(name+".card");
		try {
			FileWriter out = new FileWriter(f.getName());
			for(int i = 0; i < 10; i++){
				out.append(randomString(10)+System.lineSeparator());
			}
			out.flush();
			out.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private String randomString( int len ){
	   StringBuilder sb = new StringBuilder( len );
	   for( int i = 0; i < len; i++ ) 
	      sb.append( abc.charAt( rnd.nextInt(abc.length()) ) );
	   return sb.toString();
	}
	
	public List<String> getContent(){
		List<String> list = new ArrayList<String>();
		try {
			BufferedReader reader = new BufferedReader(new FileReader (this.f));
			String line = null;
			while((line = reader.readLine()) != null) {
	            list.add(line);
			}
			reader.close();
	            
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return list;
	}

}
