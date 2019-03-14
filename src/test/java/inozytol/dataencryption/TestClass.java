package inozytol.dataencryption;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.spec.PBEParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import java.nio.file.Path;
import java.nio.file.Files;


import java.security.SecureRandom;

public class TestClass {

    @Test
    void testParametersToAndFromBytes() {
	int itCountOriginal = 1009;
	int itCountRead = 0;

	byte [] saltOriginal = {0x11, 0x22, 0x12, 0x17};
	byte [] saltRead = null;

	byte [] ivOriginal = {0x02, 0x1F, 0x32, 0x17, 0x01};
	byte [] ivRead = null;

	
	byte [] output = Cryptest.parametersToBytes(itCountOriginal, saltOriginal, ivOriginal);
	PBEParameterSpec pbeps = Cryptest.parametersFromBytes(output);

	itCountRead = pbeps.getIterationCount();
	saltRead = pbeps.getSalt();
	AlgorithmParameterSpec aps = pbeps.getParameterSpec();
	ivRead = ((IvParameterSpec) aps).getIV();
	


	assertEquals(itCountOriginal, itCountRead, "Iteration count read wrong");
	assertTrue(Arrays.equals(saltOriginal, saltRead), "Salt wrong");
	assertTrue(Arrays.equals(ivOriginal, ivRead), "Iv wrong");        
    }


    @Test
    void testEncryptionDecryption() {
	byte [] dataToEncrypt = new byte[]{122, -17, 23, -98, 28, 19};

	byte [] encrypted = null;
	byte [] decrypted = null;
	
       	char [] password = {'u', 'a', 'b', 'c', 'd', 'e', 'f', 'g'};	
	int itCount = 10204;

	StreamCrypt sc = new Cryptest();
	
	try (ByteArrayInputStream bais = new ByteArrayInputStream(dataToEncrypt);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    sc.encryptDataStreamToStream(password, itCount, bais,baos);
	    encrypted = baos.toByteArray();
	    
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	} catch (Exception e) {System.out.println(e);}

	// Reading metadata for decryption

	sc = new Cryptest();

	try (	ByteArrayInputStream bais = new ByteArrayInputStream(encrypted);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    itCount = sc.decryptDataStreamToStream(password,bais,baos);
	    decrypted = baos.toByteArray();
				      
	} catch (IOException e){System.err.println(e);}
	assertTrue(Arrays.equals(dataToEncrypt, decrypted));
    }


    @Test
    void testEncryptionDecryptionLong() {
	byte [] dataToEncrypt = new byte[500000];
	byte [] randomStuff = new byte[100];
	int randomStuffCounter = 0;

	StreamCrypt sc = new Cryptest();
	
	new SecureRandom().nextBytes(randomStuff); //generating random bytes for salt
	for(int i = 0; i < dataToEncrypt.length; i++){
	    dataToEncrypt[i] = randomStuff[randomStuffCounter++];
	    if(randomStuffCounter == randomStuff.length) randomStuffCounter = 0;
	}
	
	byte [] encrypted = null;
	byte [] decrypted = null;
	
       	char [] password = {'u', 'a', 'b', 'c', 'd', 'e', 'f', 'g'};	
	int itCount = 10204;
	
	try (ByteArrayInputStream bais = new ByteArrayInputStream(dataToEncrypt);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    sc.encryptDataStreamToStream(password, itCount, bais,baos);
	    encrypted = baos.toByteArray();
	    
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	} catch (Exception e) {System.out.println(e);}


	
	// Reading metadata for decryption

	sc = new Cryptest();

	try (	ByteArrayInputStream bais = new ByteArrayInputStream(encrypted);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();){

	    sc.decryptDataStreamToStream(password,bais,baos);
	    decrypted = baos.toByteArray();
				      
	} catch (IOException e){System.err.println(e);}
	
	assertTrue(Arrays.equals(dataToEncrypt, decrypted));
    }

    @Test
    void testEncryptionWithNegativeItCount() {
	byte [] dataToEncrypt = new byte[]{122, -17, 23, -98, 28, 19};

	byte [] encrypted = null;
	byte [] decrypted = null;
	
       	char [] password = {'u', 'a', 'b', 'c', 'd', 'e', 'f', 'g'};	
	int itCount = -17;

	StreamCrypt sc = new Cryptest();
	
	try (ByteArrayInputStream bais = new ByteArrayInputStream(dataToEncrypt);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    sc.encryptDataStreamToStream(password, itCount, bais,baos);
	    encrypted = baos.toByteArray();
	    
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	} catch (Exception e) {System.out.println(e);}

	// Reading metadata for decryption

	sc = new Cryptest();
	
	try (	ByteArrayInputStream bais = new ByteArrayInputStream(encrypted);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    itCount = sc.decryptDataStreamToStream(password,bais,baos);
	    decrypted = baos.toByteArray();
				      
	} catch (IOException e){System.err.println(e);}
	assertTrue(Arrays.equals(dataToEncrypt, decrypted));
    }

    // testing whether function will work for buffered streams and files
    @Test
    void testWorkingWithBufferedStreams() {
       	char [] password = {'u', 'a', 'b', 'c', 'd', 'e', 'f', 'g'};	
	int itCount = 10204;
	StreamCrypt sc = new Cryptest();

	// Create me temporary files

	Path fileToStore = null;
	Path encryptedFile = null;
	Path finalFile = null;

	
	try {
	    fileToStore = Files.createTempFile("","");
	    encryptedFile = Files.createTempFile("","");
	    finalFile = Files.createTempFile("","");
	    System.out.println(fileToStore);
	} catch (Exception e) {
	    System.out.println("Error creating temporary files");
	}

	// create me some rubbish into the file
	
	byte [] randomStuff = new byte[100];
	int randomStuffCounter = 0;

	int lengthOfFile = 2000;
	
        try ( OutputStream bos = new BufferedOutputStream(new FileOutputStream(fileToStore.toFile()))) {
	    new SecureRandom().nextBytes(randomStuff);
	    for(int i = 0; i < lengthOfFile; i++){
		bos.write(randomStuff[randomStuffCounter++]);
		if(randomStuffCounter == randomStuff.length) randomStuffCounter = 0;
	    }  
	}
	catch (Exception e) {
	    System.out.println("Error in buffered files test function, while writing rubbish to file");
	    System.out.println(e);
	}

	//  encrypt file
	try (InputStream bis = new BufferedInputStream(new FileInputStream(fileToStore.toFile()));
	     OutputStream bos = new BufferedOutputStream(new FileOutputStream(encryptedFile.toFile()))) {
	    sc.encryptDataStreamToStream(password, itCount, bis,bos);
	}
	catch (Exception e) {
	    System.out.println("Error in buffered files test function during encryption");
	    System.out.println(e);
	}

	
	// convert encrypted file to decrypted file
	try (InputStream bis = new BufferedInputStream(new FileInputStream(encryptedFile.toFile()));
	     OutputStream bos = new BufferedOutputStream(new FileOutputStream(finalFile.toFile()))) {
	   
	    sc.decryptDataStreamToStream(password,bis,bos);
	}
	catch (Exception e) {
	    System.out.println("Error in buffered files test function");
	    System.out.println(e);
	}


        boolean binaryFilesEqualTestResult = binaryFilesAreEqual(fileToStore, finalFile);

	//clean up (delete files used)
	try {
	    for (Path file : new Path[]{finalFile, encryptedFile, fileToStore}) {
		if (Files.exists(file)) Files.delete(file);
	    }
	} catch (IOException e) {
	    System.out.println("Error occured during deleting temporary files. " + e);
	}

	assertTrue(binaryFilesEqualTestResult);

    }

    
    /** 
     * returns true if files are the same
     * returns false if any of the files does not exist
     */
    boolean binaryFilesAreEqual(Path file1, Path file2) {
        if(!Files.exists(file1) || !Files.exists(file2)) return false;

	boolean ret = false;
	int temp1;
	int temp2;
        
        try (InputStream bis1 = new BufferedInputStream(new FileInputStream(file1.toFile())); InputStream bis2 = new BufferedInputStream(new FileInputStream(file2.toFile()))) {
	    ret = true;
            do {
		temp1 = bis1.read();
		temp2 = bis2.read();
	    } while (temp1 == temp2 && temp1 != -1 && temp2 != -1);
	    if (temp1 != temp2) ret = false;
        } catch (IOException e) {
            System.out.println("Exception has occured while comparing files");
	    System.out.println(e+"");
        }
	return ret;
    }
}

