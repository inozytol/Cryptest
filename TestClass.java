import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.spec.PBEParameterSpec;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import java.util.Arrays;

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
}

