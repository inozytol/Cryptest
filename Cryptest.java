import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException; //for SecretKeyFactory
import java.security.SecureRandom;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;


import java.nio.charset.StandardCharsets; //needed for specifing charset for getBytes
import java.nio.charset.Charset;


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
	Charset dataCharset = StandardCharsets.UTF_8;
	byte [] dataToEncrypt = "This is plaintext".getBytes(dataCharset);

	

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

	//iteration count from PKCS #5
	int iterationCount = 1000;
	
	//salt from java documentation	
	byte[] salt = new byte[10];
	new SecureRandom().nextBytes(salt); //generating random bytes for salt

	PBEParameterSpec pbeParams = new PBEParameterSpec(salt, iterationCount);


	String pbeCipherAlgo = "PBEWithHmacSHA256AndAES_128";
	Cipher c2 = null;
	try{
	    //Creating cipher object for AES 128bit encryption with padding
	    c2 = Cipher.getInstance(pbeCipherAlgo);
	}
	catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create Cipher object for specified algorithm " + cipherAlgo);
	    System.exit(0);
			       
	}catch (NoSuchPaddingException e){
	    System.err.println("Can't create Cipher object for  padding " + cipherAlgo);
	    System.exit(0);
	}

	// ENCRYPTION INIT
	// before encryption cipher object must be initialized with mode, key and pbe params
	try{
	    c2.init(Cipher.ENCRYPT_MODE, secretKey, pbeParams);
	} catch (InvalidKeyException e) {
	    System.err.println("Invalid key for encryption");
	    System.exit(0);
	} catch (InvalidAlgorithmParameterException e) {
	    System.err.println("Invalid algorithm parameter for encryption");
	    System.exit(0);
	}


	// ENCRYPTION FINAL
	byte [] buffer = null;
	try {
	    buffer = c2.doFinal(dataToEncrypt);
	} catch (IllegalBlockSizeException e) {
	    System.err.println("Invalid block size for encryption");
	    System.exit(0);
	} catch (BadPaddingException e) {
	    System.err.println("Bad padding for encryption");
	    System.exit(0);
	}

	// DECRYPTION INIT
	// before encryption cipher object must be initialized with mode, key and pbe params
	try{
	    c2.init(Cipher.DECRYPT_MODE, secretKey);
	} catch (InvalidKeyException e) {
	    System.err.println("Invalid key for decryption");
	    System.exit(0);
	}


	// DECRYPTION FINAL
	byte [] outBuffer = null;
	try {
	    outBuffer = c2.doFinal(buffer);
	} catch (IllegalBlockSizeException e) {
	    System.err.println("Invalid block size for decryption");
	    System.exit(0);
	} catch (BadPaddingException e) {
	    System.err.println("Bad padding for decryption");
	    System.exit(0);
	}

	System.out.println(outBuffer);
	for(byte b : outBuffer) System.out.print(b + " ");
	System.out.println("");
	for(byte b : outBuffer) System.out.print(Integer.toBinaryString(b) + " ");
	System.out.println("");
	System.out.println(new String(outBuffer, dataCharset));

    }

}
