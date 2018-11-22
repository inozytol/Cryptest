import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException; //for SecretKeyFactory

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


	//creating passphrase and data to encrypt variables
	
	byte [] dataToEncrypt = "This is plaintext".getBytes(StandardCharsets.UTF_8);

        char [] passphrase = {'h','e','l','l','o'};


	// printing byte and char arrays - to investigate how it is done
	for(byte b : dataToEncrypt) System.out.print(b + " ");
	System.out.println("");
	for(byte b : dataToEncrypt) System.out.print(Integer.toBinaryString(b) + " ");
	System.out.println("");
	System.out.println(dataToEncrypt);
	System.out.println(passphrase);

	// ==== ENCRYPTING PLAINTEXT USING PASSWORD =======

	//algorithm name for SecretKeyFactory
	String secretKeyFactoryAlgoName = "PBEWithHmacSHA256AndAES_128";
        // SecretKeyFactory is needed to convert PBEKeySpec into SecretKey for Cipher.init
	SecretKeyFactory skf = null;
	try {
	     skf = SecretKeyFactory.getInstance(secretKeyFactoryAlgoName);
	} catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create SecretKeyFactory object for specified algorithm " 
			       + secretKeyFactoryAlgoName);
	    System.exit(0);
	}

	PBEKeySpec keySpec = new PBEKeySpec(passphrase);
	SecretKey secretKey = null;
	try {
	    secretKey = skf.generateSecret(keySpec);
	} catch (InvalidKeySpecException e) {
	    System.out.println("Invalid key spec for key factory");
	    System.exit(0);
	}
	
	
	
	
    }

}
