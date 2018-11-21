import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.security.NoSuchAlgorithmException;

import java.nio.charset.StandardCharsets; //needed for specifing charset for getBytes


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

	// ==== ENCRYPTING PLAINTEXT USING PASSWORD =======
	byte [] dataToEncrypt = "This is plaintext".getBytes(StandardCharsets.UTF_8);

        char [] passphrase = {'h','e','l','l','o'};
	
    }

}
