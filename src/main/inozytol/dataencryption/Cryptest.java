package inozytol.dataencryption;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
 
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
import javax.crypto.spec.SecretKeySpec;

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
import java.io.InputStream;
import java.io.OutputStream;

import java.util.Arrays;

public class Cryptest implements StreamCrypt{

    private static String keyAlgo = "AES";
    private static String pbeCipherAlgo = "PBEWithHmacSHA256AndAES_128";
    private static int itThreshold = 1000;

    private static final Logger logger = LogManager.getLogger();
    
    public static void main(String [] args){
	
	// ============ FUTURE GOALS HERE =============


	// Using Hmac on encrypted data and metada
	// there is class for hmac


	// next step would be wrapping key
	// this way we could change password without decrypting and encryptin all the data
	    
    }


    /**
     * Function for encrypting data from stream and sending it into another stream
     * Function will get instance of cipher and initalize it
     * @param pass password for enecryption
     * @param itCount iteration count for turning password into key
     * @param is is a stream containg data for encryption
     * @param os is a target stream for encrypted data
     * @return byte length of decrypted data, -1 if error was encountered
     */
    public int encryptDataStreamToStream(char [] pass,
					       int itCount,
					       InputStream is,
					       OutputStream os) throws IOException {
	char [] password = Arrays.copyOf(pass, pass.length);
	byte[] salt = new byte[10];
	new SecureRandom().nextBytes(salt);

	if(itCount < itThreshold) {
	    //TODO: LOG setting minimum itCount
	    logger.info("Iteration count for encryption too low. (" + itCount + "). Setting: " + itThreshold);
	    itCount = itThreshold;
	}
	
	SecretKeySpec secretKeyForEncryption = getSecretKeyForPBECipher(password, salt, itCount);
	
	Cipher encryptingCipher = getInstanceOfPBECipher();
	
	// before encryption cipher object must be initialized with mode and key
	try{
	    encryptingCipher.init(Cipher.ENCRYPT_MODE, secretKeyForEncryption);
	} catch (InvalidKeyException e) {
	    System.err.println("Invalid key for encryption: " + e.getMessage());
	    System.err.println("Got " + secretKeyForEncryption.getAlgorithm());
	    System.exit(1);
	}
	CipherInputStream cis = new CipherInputStream(is,encryptingCipher);

	byte [] iv = encryptingCipher.getIV();
	byte [] output = Cryptest.parametersToBytes(itCount, salt, iv);

	os.write(output);
	int temp;
	int counter = 0;
	while((temp=cis.read())!=-1) {
	    counter++;
	    os.write(temp);
	}
	return counter;
    }

    /**
     * Function for decrypting data from stream and sending it into another stream
     * @param pass password for decryption
     * @param is is a stream containg data in format native to this class
     * @param os is a target stream for decrypted data
     * @return byte length of decrypted data, -1 if error was encountered
     */
    public int decryptDataStreamToStream(char [] pass,
						InputStream is,
						OutputStream os) throws IOException {
	char [] password = Arrays.copyOf(pass, pass.length);
	Cipher decryptingCipher = getInstanceOfPBECipher();
	// Read whole file contents to temp variable
	    
	byte [] tempBytesRead = new byte[16];
	byte [] tempBytesToWrite = new byte[16];

	int lengthOfInput = -1;
	int lengthOfOutput = -1;

	int ret = 0;
	    
	lengthOfInput = is.read(tempBytesRead, 0, 4);
	int lengthOfMetadata = -1;

	byte [] metadata = null;

	
	ByteBuffer bb = ByteBuffer.allocate(4);

	bb.put(tempBytesRead, 0, 4); 
	bb.rewind();
	lengthOfMetadata = bb.getInt();
	metadata = new byte[lengthOfMetadata]; //four first bytes were length of metadata

	lengthOfInput = is.read(metadata,4, lengthOfMetadata-4);
	

	try{   
	    PBEParameterSpec pbeps = Cryptest.parametersFromBytes(metadata);
	    IvParameterSpec ivps = (IvParameterSpec) pbeps.getParameterSpec();
	    
	    
	    SecretKeySpec secretKeyForDecrypt = getSecretKeyForPBECipher(password,
									 pbeps.getSalt(),
									 pbeps.getIterationCount());
	    decryptingCipher.init(Cipher.DECRYPT_MODE, secretKeyForDecrypt, ivps);
	    
	}

	catch (InvalidKeyException e) {
	    System.err.println("Invalid key for decryption: " + e + e.getMessage());
	    return -1;
	} catch (InvalidAlgorithmParameterException e) {
	    System.err.println("Invalid algorithm parameter exception" + e);
	    return -1;
	}  

	try {
	    while((lengthOfInput=is.read(tempBytesRead))!=-1){
		lengthOfOutput = decryptingCipher.update(tempBytesRead, 0, lengthOfInput, tempBytesToWrite);
		if(lengthOfOutput>0) ret += lengthOfOutput;
		os.write(tempBytesToWrite, 0 ,lengthOfOutput);
	    }
	    //we need to do final without input
	    lengthOfOutput = decryptingCipher.doFinal(tempBytesToWrite, 0);
	    if(lengthOfOutput > 0) {
		os.write(tempBytesToWrite, 0, lengthOfOutput);
		ret += lengthOfOutput;
	    }
	
	}  catch (ShortBufferException e) {
	    System.out.println("Buffer too short!" + e);
	    return -1;
	} catch (javax.crypto.IllegalBlockSizeException e) {
	    System.out.println("Illegal block size " + e);
	    return -1;
	} catch (javax.crypto.BadPaddingException e) {
	    System.out.println("Bad padding " + e);
	    return -1;
	}
       
	return ret;
    }

    /**
     * Function for getting Cipher instance for AES/CBC/PKCS5Padding algorithm
     * Convieniently should take care of errors (which probably should not happen)
     * @return instance of cipher object for AES/CBC/PKCS5Padding algorithm
     */
    static Cipher getInstanceOfPBECipher() {

        String cipherAlgo = "AES/CBC/PKCS5Padding";
    	Cipher cipherInstance = null;
	try{
	    //Creating cipher object for AES 128bit encryption with padding
	    cipherInstance = Cipher.getInstance(cipherAlgo);
	}
	catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create Cipher object for specified algorithm " + pbeCipherAlgo);
			       
	}catch (NoSuchPaddingException e){
	    System.err.println("Can't create Cipher object for  padding " + pbeCipherAlgo);
	}
	return cipherInstance;
    }

    /**
     * Function for generating secret key from password, salt and iteration count
     */
    static SecretKeySpec getSecretKeyForPBECipher(char []  password,
							 byte [] salt,
							 int itCount) {
	SecretKey secretKey = null;
	//needed to add length, otherwise for this algo factory was complaining
	PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, itCount, 128);
	
	String secretKeyFactoryAlgo = "PBKDF2WithHmacSHA256";

	// SecretKeyFactory is needed to convert PBEKeySpec into SecretKey for Cipher.init
	SecretKeyFactory skf = null;
	try {
	    skf = SecretKeyFactory.getInstance(secretKeyFactoryAlgo);
	} catch (NoSuchAlgorithmException e){
	    System.err.println("Can't create SecretKeyFactory object for specified algorithm " 
			       + secretKeyFactoryAlgo + e);
	}

	try {
	    secretKey = skf.generateSecret(pbeKeySpec);
	} catch (InvalidKeySpecException e) {
	    System.err.println("Invalid key spec for key factory" + e);
	}
	// attaches algorithm info to secret key, as required by cipher init of used algo
	// SecretKey + "AES" algo name => SecretKeySpec
	SecretKeySpec skey = new SecretKeySpec(secretKey.getEncoded(), "AES"); 
	return skey;
    }

   
    /**
     * Converts iteration count, salt and initialization vector into raw bytes
     * @param iterationCount iteration count for key processing
     * @param salt salt for hashing string password into secret key (?)
     * @param iv initialization vector for CBC AES encryption
     * @return byte array beginning with its length, and containing parameter values. Arrays are precluded with their lengths
     */
    static byte[] parametersToBytes(int iterationCount, byte [] salt, byte [] iv){
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

    /** 
     * Converts byte array returned by {@link #parametersToBytes(int iterationCount, byte [] salt, byte [] iv) parametersToBytes} function into PBEParameterSpec
     * Probably can be private
     * 
     */
    static PBEParameterSpec parametersFromBytes(byte [] data){
	int start = 4;  // don't ignore first four bytes as they dont contain data length
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
