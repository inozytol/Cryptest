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

	

        //char [] passphrase = {'h','e','l','l','o'};
	char [] passphrase = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};

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
	    System.exit(1);
	}

	PBEKeySpec keySpec = new PBEKeySpec(passphrase);
	SecretKey secretKey = null;
	try {
	    secretKey = skf.generateSecret(keySpec);
	} catch (InvalidKeySpecException e) {
	    System.out.println("Invalid key spec for key factory");
	    System.exit(1);
	} 

	//iteration count from PKCS #5
	int iterationCount = 1024;
	
	//salt from java documentation	
	byte[] salt = new byte[10];
	new SecureRandom().nextBytes(salt); //generating random bytes for salt

	PBEParameterSpec pbeParams = new PBEParameterSpec(salt, iterationCount);



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

	// Saving metadata (iv, salt and iteration count along with encrypted data)
	// Format: iteration count (integer, 4 bytes), salt length (integer, 4 bytes), salt (byte array), iv length (integer, 4 bytes), iv (byte array), encrypted data
	java.nio.ByteBuffer bb = java.nio.ByteBuffer.allocate(15);
	bb.putInt(15);


	// Checking what kind of ByteBuffer did we get since byte buffer is abstract
	System.out.println(bb.getClass().getName());
	System.out.println((java.nio.ByteBuffer.allocate(1)).getClass().getName());
	
	
       

	Cipher encryptingCipherForMetadata = getInstanceOfPBECipher();
	
	// lets try to put all the data into keyspec and init cipher only with secretkey

	char [] password2 = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
	
	//	byte[] saltForMetadata = new byte[12];
	int itCountMeta = 1024;
	//	new SecureRandom().nextBytes(saltForMetadata);
	PBEKeySpec pbekeyspecForMetadata = new PBEKeySpec(password2, salt, itCountMeta);

	//creating key factory

	//algorithm name for SecretKeyFactory
	String secretKeyFactoryAlgoNameMeta = "PBEWithHmacSHA256AndAES_128";
        // SecretKeyFactory is needed to convert PBEKeySpec into SecretKey for Cipher.init
	SecretKeyFactory skfmeta = null;
	try {
	     skfmeta = SecretKeyFactory.getInstance(secretKeyFactoryAlgoNameMeta);
	} catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create SecretKeyFactory object for specified algorithm " 
			       + secretKeyFactoryAlgoName);
	    System.exit(1);
	}

       
	SecretKey secretKeyMeta = null;
	try {
	    secretKeyMeta = skfmeta.generateSecret(pbekeyspecForMetadata);
	} catch (InvalidKeySpecException e) {
	    System.out.println("Invalid key spec for key factory");
	    System.exit(1);
	} 
	
	// initializeCipherObject(encryptingCipherForMetadata, 1000, );

	
	// ENCRYPTION INIT
	// before encryption cipher object must be initialized with mode, key and pbe params
	try{
	    encryptingCipherForMetadata.init(Cipher.ENCRYPT_MODE, secretKeyMeta);
	} catch (InvalidKeyException e) {
	    System.err.println("Invalid key for encryption: " + e + e.getMessage());
	    System.exit(1);
	}

	byte [] ivForMeta = encryptingCipherForMetadata.getIV();
	System.out.println("IV for metadata length: " + ivForMeta.length);

	int metaLength = ivForMeta.length;

	ByteBuffer bbmeta = ByteBuffer.allocate(4);
	bbmeta.putInt(metaLength);

	System.out.println("Buffer state: " + bbmeta);

	try (FileInputStream fis = new FileInputStream("foo");
	     FileOutputStream fos = new FileOutputStream("foo_encrypt_meta")){
	    CipherInputStream cis = new CipherInputStream(fis,encryptingCipherForMetadata);

	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	}


	
	// Reading metadata for decryption

	Cipher decryptingCipherForMetadata = getInstanceOfPBECipher();

	try (FileInputStream fis = new FileInputStream("foo_encrypt_meta");
	     FileOutputStream fos = new FileOutputStream("foo_decrypt_meta")){
	    bb.clear();
	    byte [] tempInt = new byte[4];
	    fis.read(tempInt);
	    bb.put(tempInt);//reading length of iv array
	    bb.rewind();
	    int ivArrayLength = bb.getInt();     // reading length of iv array (integer, 4 bytes)
	    System.out.println(ivArrayLength);
	    byte [] ivArray = new byte[ivArrayLength];  

	    
	    System.out.println("iv array read: " + fis.read(ivArray) + " bytes"); // reading iv array (16 bytes this time)

	    bb.clear();
	    fis.read(tempInt);
	    bb.put(tempInt);
	    bb.rewind();
	    int saltArrayLength = bb.getInt();
	    System.out.println(saltArrayLength);
	    byte [] salt2 = new byte[saltArrayLength];

	    fis.read(salt2);
	    System.out.println("Salt read: ");
	    for(byte b : salt2) System.out.print(Integer.toBinaryString(b) + " ");
	    
	    bb.clear();
	    fis.read(tempInt);
	      bb.put(tempInt);
	    bb.rewind();
	    int itcount2 = bb.getInt();
	    System.out.println("It count: "  + itcount2);
	    itcount2 = 1024;
	    SecretKey skm = getSecretKeyForPBECipher(password2, salt2, itcount2);
	    //	    decryptingCipherForMetadata.init(Cipher.DECRYPT_MODE, skm, new IvParameterSpec(ivArray));

	    PBEParameterSpec pbeParamsDecFromFile = new PBEParameterSpec(salt2, itcount2, new IvParameterSpec(ivArray));
	    decryptingCipherForMetadata.init(Cipher.DECRYPT_MODE, skm, pbeParamsDecFromFile);   
	    // CipherInputStream cis = new CipherInputStream(fis,decryptingCipherForMetadata);

	    byte [] tempBytesFromFile = new byte[10024];
	    byte [] tempBytesToFile = new byte[10024];

	    int bytesReadCount = fis.read(tempBytesFromFile);
	    System.out.println("Bytes read count equals: " + bytesReadCount);
	    int bytesOutputCount = decryptingCipherForMetadata.doFinal(tempBytesFromFile, 0, bytesReadCount, tempBytesToFile);
	    fos.write(tempBytesToFile, 0, bytesOutputCount);
	    
	    //while((temp=cis.read())!=-1) fos.write(temp);
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	} catch (InvalidKeyException e) {
		System.err.println("Invalid key for decryption: " + e + e.getMessage());
	} catch (InvalidAlgorithmParameterException e) {
		    System.err.println("Invalid algorithm" + e);
	}//catch (NoSuchAlgorithmException e){
	// System.err.println("Can't create Cipher object for specified algorithm " + e);
			       
	//	}
	catch (ShortBufferException e) {
	    System.out.println("Buffer too short!" + e);
	}  catch (javax.crypto.IllegalBlockSizeException e) {
	    System.out.println("Illegal block size " + e);
	} catch (javax.crypto.BadPaddingException e) {
	    System.out.println("Bad padding " + e);
	}

	
	// Use ByteBuffer as it can convert byte [] into integer


	// Using Hmac on encrypted data and metada
	// there is class for hmac


	// next step would be wrapping key
	    

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
}
