import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.security.NoSuchAlgorithmException;

/*
CREATING KEY FROM BYTE ARRAY
https://docs.oracle.com/javase/8/docs/api/index.html?javax/crypto/KeyGenerator.html
public class SecretKeySpec
extends Object
implements KeySpec, SecretKey

This class specifies a secret key in a provider-independent fashion.

It can be used to construct a SecretKey from a byte array, without having to go through a (provider-based) SecretKeyFactory. 
*/
//byte[] b = string.getBytes(StandardCharsets.UTF_8); 


class Cryptest {
    private static String cipherAlgo = "AES/CBC/PKCS5Padding";
    private static String keyAlgo = "AES";
    
    public static void main(String [] args){

	try{
	    //Creating cipher object for AES 128bit encryption with padding
	    Cipher c = Cipher.getInstance(cipherAlgo);
	}
	catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create Cipher object for specified algorithm " + cipherAlgo);
	    System.exit(0);
			       
	}catch (NoSuchPaddingException e){
	    System.err.println("Can't create Cipher object for  padding " + cipherAlgo);
	    System.exit(0);
	}


	try{
	//Creating key generator from factory for AES
	    KeyGenerator kg = KeyGenerator.getInstance(keyAlgo);
	}
	catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create keyGenerator object for specified algorithm " + keyAlgo);
	    System.exit(0);
			       
	}
	
    }

}
