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
	
	try (ByteArrayInputStream bais = new ByteArrayInputStream(dataToEncrypt);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    Cryptest.encryptDataStreamToStream(password, itCount, bais,baos);
	    encrypted = baos.toByteArray();
	    
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	} catch (Exception e) {System.out.println(e);}

	// Reading metadata for decryption

	try (	ByteArrayInputStream bais = new ByteArrayInputStream(encrypted);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    itCount = Cryptest.decryptDataStreamToStream(password,bais,baos);
	    decrypted = baos.toByteArray();
				      
	} catch (IOException e){System.err.println(e);}
	assertTrue(Arrays.equals(dataToEncrypt, decrypted));
    }


    @Test
    void testEncryptionDecryptionLong() {
	byte [] dataToEncrypt = new byte[500000];
	byte [] randomStuff = new byte[100];
	int randomStuffCounter = 0;
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

	    Cryptest.encryptDataStreamToStream(password, itCount, bais,baos);
	    encrypted = baos.toByteArray();
	    
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	} catch (Exception e) {System.out.println(e);}


	
	// Reading metadata for decryption


	try (	ByteArrayInputStream bais = new ByteArrayInputStream(encrypted);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();){

	    Cryptest.decryptDataStreamToStream(password,bais,baos);
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
	
	try (ByteArrayInputStream bais = new ByteArrayInputStream(dataToEncrypt);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    Cryptest.encryptDataStreamToStream(password, itCount, bais,baos);
	    encrypted = baos.toByteArray();
	    
	} catch (IOException e) {
	    System.err.println("Error while reading/writing file: " + e);
	    System.exit(0);
	} catch (Exception e) {System.out.println(e);}

	// Reading metadata for decryption

	try (	ByteArrayInputStream bais = new ByteArrayInputStream(encrypted);
		ByteArrayOutputStream baos = new ByteArrayOutputStream()){

	    itCount = Cryptest.decryptDataStreamToStream(password,bais,baos);
	    decrypted = baos.toByteArray();
				      
	} catch (IOException e){System.err.println(e);}
	assertTrue(Arrays.equals(dataToEncrypt, decrypted));
    }

}

