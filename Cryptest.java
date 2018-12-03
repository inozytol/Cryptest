import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.CipherInputStream;
import javax.crypto.ShortBufferException;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException; //for SecretKeyFactory
import java.security.SecureRandom;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.AlgorithmParameters;

import java.nio.charset.StandardCharsets; //needed for specifing charset for getBytes
import java.nio.charset.Charset;
import java.nio.ByteBuffer;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.util.Arrays;

public class Cryptest {
    private static String cipherAlgo = "AES/CBC/PKCS5Padding";
    private static String keyAlgo = "AES";
    private static String pbeCipherAlgo = "PBEWithHmacSHA256AndAES_128";
    public static void main(String [] args){
	
       	char [] password = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};	
	int itCount = 1024;

	byte[] salt = new byte[10];
	new SecureRandom().nextBytes(salt); //generating random bytes for salt
	
	SecretKey secretKeyForEncryption = getSecretKeyForPBECipher(password, salt, itCount);
	
	// ENCRYPTION INIT
	
	Cipher encryptingCipher = getInstanceOfPBECipher();
	
	// before encryption cipher object must be initialized with mode, key and pbe params
	// pbe parames optional?
	try{
	    encryptingCipher.init(Cipher.ENCRYPT_MODE, secretKeyForEncryption);
	} catch (InvalidKeyException e) {
	    System.err.println("Invalid key for encryption: " + e + e.getMessage());
	    System.exit(1);
	}

	try (FileInputStream fis = new FileInputStream("foo");
	     FileOutputStream fos = new FileOutputStream("foo_encrypt")){

	    CipherInputStream cis = new CipherInputStream(fis,encryptingCipher);

	    byte [] iv = encryptingCipher.getIV();
	    byte [] output = Cryptest.parametersToBytes(itCount, salt, iv);

	    fos.write(output);
	    int temp;
	    int counter = 0;
	    while((temp=cis.read())!=-1) {
		counter++;
		fos.write(temp);
	    }
	    System.out.println("Wrote " + output.length + " bytes of metada " +
			       "and " + counter + " bytes of encrypted data");
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	}


	
	// Reading metadata for decryption

	//Cipher decryptingCipher = getInstanceOfPBECipher();

	try (FileInputStream fis = new FileInputStream("foo_encrypt");
	     FileOutputStream fos = new FileOutputStream("foo_decrypt")){

	    // Read whole file contents to temp variable
	    
	    byte [] tempBytesFromFile = new byte[10024];
	    byte [] tempBytesToFile = new byte[10024];

	    int lengthOfInput = -1;
	    int lengthOfOutput = -1;
	    
	    lengthOfInput = fis.read(tempBytesFromFile);


	    
	    ByteBuffer bb = ByteBuffer.allocate(4);

	    bb.put(tempBytesFromFile, 0, 4); 
	    bb.rewind();
	    int lengthOfMetadata = bb.getInt();

	    byte [] metadata = Arrays.copyOf(tempBytesFromFile, lengthOfMetadata);
	    
	    System.out.println("Read from input: " + lengthOfInput + " total, " +
			       lengthOfMetadata + " is metadata");
	    
	    PBEParameterSpec pbeps = Cryptest.parametersFromBytes(metadata);

	    Cipher decryptingCipher = getInstanceOfPBECipher();

	    SecretKey secretKeyForDecrypt = getSecretKeyForPBECipher(password,
								     pbeps.getSalt(),
								     pbeps.getIterationCount());

	    
	    decryptingCipher.init(Cipher.DECRYPT_MODE, secretKeyForDecrypt, pbeps);
	    lengthOfOutput = decryptingCipher.doFinal(tempBytesFromFile,
						      lengthOfMetadata,
						      lengthOfInput-lengthOfMetadata,
						      tempBytesToFile);

	    fos.write(tempBytesToFile, 0, lengthOfOutput);
						    


	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	} catch (InvalidKeyException e) {
		System.err.println("Invalid key for decryption: " + e + e.getMessage());
	} catch (InvalidAlgorithmParameterException e) {
		    System.err.println("Invalid algorithm" + e);
	}
	catch (ShortBufferException e) {
	    System.out.println("Buffer too short!" + e);
	}  catch (javax.crypto.IllegalBlockSizeException e) {
	    System.out.println("Illegal block size " + e);
	} catch (javax.crypto.BadPaddingException e) {
	    System.out.println("Bad padding " + e);
	}

	
	// ============ FUTURE GOALS HERE =============


	// Using Hmac on encrypted data and metada
	// there is class for hmac


	// next step would be wrapping key
	// this way we could change password without decrypting and encryptin all the data
	    

    }

	
    public static Cipher getInstanceOfPBECipher() {
    	Cipher cipherInstance = null;
	try{
	    //Creating cipher object for AES 128bit encryption with padding
	    cipherInstance = Cipher.getInstance(pbeCipherAlgo);
	}
	catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create Cipher object for specified algorithm " + pbeCipherAlgo);
			       
	}catch (NoSuchPaddingException e){
	    System.err.println("Can't create Cipher object for  padding " + pbeCipherAlgo);
	}
	return cipherInstance;
    }

    public static SecretKey getSecretKeyForPBECipher(char []  password, byte [] salt, int itCount) {
	SecretKey secretKey = null;
	PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, itCount);

	//creating key factory
	String secretKeyFactoryAlgo = "PBEWithHmacSHA256AndAES_128";
	// SecretKeyFactory is needed to convert PBEKeySpec into SecretKey for Cipher.init

	SecretKeyFactory skf = null;
	try {
	    skf = SecretKeyFactory.getInstance(secretKeyFactoryAlgo);
	} catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create SecretKeyFactory object for specified algorithm " 
			       + secretKeyFactoryAlgo);
	}

	try {
	    secretKey = skf.generateSecret(pbeKeySpec);
	} catch (InvalidKeySpecException e) {
	    System.err.println("Invalid key spec for key factory");
	}

	return secretKey;
    }


    public static byte[] parametersToBytes(int iterationCount, byte [] salt, byte [] iv){
	int saltLength = salt.length;
	int ivLength = iv.length;
	//4 bytes for data length, 4 bytes for iteration count + 2x4 bytes for salt and iv lengths
	int outputLength = 4 + 4 + saltLength + 4 + iv.length + 4;
	int index = 0;
	
        ByteBuffer output = ByteBuffer.allocate(outputLength);

	output.putInt(outputLength);
	output.putInt(iterationCount);
	output.putInt(saltLength);
	output.put(salt);
	output.putInt(ivLength);
	output.put(iv);
	
	return output.array();
    }

    public static PBEParameterSpec parametersFromBytes(byte [] data){
	int start = 4;  // ignore first four bytes as they contain data length
	ByteBuffer bb = ByteBuffer.wrap(data, start, 4);
	int itCount = bb.getInt(); //convert next four bytes int iteration count
	
	bb = ByteBuffer.wrap(data, start+4, 4);  // next four bytes contain salt length
	int saltLength = bb.getInt();

	// next we get salt of salt length bytes
	byte [] salt = Arrays.copyOfRange(data, start+8, start+8+saltLength);

	// next four bytes contain initialization vector
	bb = ByteBuffer.wrap(data, start+8+saltLength, 4);
	int ivLength = bb.getInt();
	
	// next we get iv of iv bytes
	byte [] iv = Arrays.copyOfRange(data, start+12+saltLength, start+12+saltLength+ivLength);
	
	return new PBEParameterSpec(salt, itCount, new IvParameterSpec(iv));
    }

    /**
     * Function containing code snipets and notes about various aspects of encryption
     */
    /*    private static void reminderCode(){
	
	// Reminders:
	// Plain text for encryption should be converted to bytes
	Charset dataCharset = StandardCharsets.UTF_8;
	byte [] dataToEncrypt = "This is plaintext".getBytes(dataCharset);

        // Passphrase should be char array, because they are easier to delete than String
	char [] passphrase = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};

	//iteration count from PKCS #5
	int iterationCount = 1024;
	
	//salt from java documentation	
	byte[] salt = new byte[10];
	new SecureRandom().nextBytes(salt); //generating random bytes for salt



	java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(15);
	bb.putInt(15);


	// Checking what kind of ByteBuffer did we get since byte buffer is abstract
	System.out.println(bb.getClass().getName());
	System.out.println((java.nio.ByteBuffer.allocate(1)).getClass().getName());

	
	Cipher c2 = null;
	try{
	    //Creating cipher object for AES 128bit encryption with padding
	    c2 = Cipher.getInstance(pbeCipherAlgo);
	}
	catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create Cipher object for specified algorithm " + cipherAlgo);
	    System.exit(1);
			       
	}catch (NoSuchPaddingException e){
	    System.err.println("Can't create Cipher object for  padding " + cipherAlgo);
	    System.exit(1);
	}

	// ENCRYPTION INIT
	// before encryption cipher object must be initialized with mode, key and pbe params
	try{
	    c2.init(Cipher.ENCRYPT_MODE, secretKey, pbeParams);
	} catch (InvalidKeyException e) {
	    System.err.println("Invalid key for encryption: " + e + e.getMessage());
	    System.exit(1);
	} catch (InvalidAlgorithmParameterException e) {
	    System.err.println("Invalid algorithm parameter for encryption");
	    System.exit(1);
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

	
	//Decryption CIPHER object creation (to avoid switching inits with different modes)
	Cipher decryptingCipher = null;
	try{
	    //Creating cipher object for AES 128bit encryption with padding
	    decryptingCipher = Cipher.getInstance(pbeCipherAlgo);
	}
	catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create Cipher object for specified algorithm " + cipherAlgo);
	    System.exit(0);
			       
	}catch (NoSuchPaddingException e){
	    System.err.println("Can't create Cipher object for  padding " + cipherAlgo);
	    System.exit(0);
	}

	PBEParameterSpec pbeParamsDec = new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(c2.getIV()));
	

	
	// DECRYPTION INIT
	// before encryption cipher object must be initialized with mode, key and pbe params
	try{
	    decryptingCipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParamsDec);
	} catch (InvalidKeyException e) {
	    System.err.println("Invalid key for decryption" + e);
	    System.exit(0);
	} catch (InvalidAlgorithmParameterException e) {
	    System.err.println("Invalid algorithm parameter for decryption" + e);
	    System.exit(0);
	}


	// DECRYPTION FINAL
	byte [] outBuffer = null;
	try {
	    outBuffer = decryptingCipher.doFinal(buffer);
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


	int temp = 0;
	//Reading data from file, encrypting it and writing it to encrypted file
	//Learning to read and write data streams (plain text data)
	try (FileInputStream fis = new FileInputStream("foo");
	     FileOutputStream fos = new FileOutputStream("foo2")){
	    while((temp=fis.read())!=-1) fos.write(temp);
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	}

	

	//Using CipherInputStream to read, encrypt, write and decrypt files

	try (FileInputStream fis = new FileInputStream("foo");
	     FileOutputStream fos = new FileOutputStream("foo_crypt")){
	    CipherInputStream cis = new CipherInputStream(fis,c2);
	    while((temp=cis.read())!=-1) fos.write(temp);
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	}

	try (FileInputStream fis = new FileInputStream("foo_crypt");
	     FileOutputStream fos = new FileOutputStream("foo_decrypt")){
	    CipherInputStream cis = new CipherInputStream(fis,decryptingCipher);
	    while((temp=cis.read())!=-1) fos.write(temp);
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	}
	} */
}
