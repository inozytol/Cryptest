package inozytol.dataencryption;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

interface StreamCrypt {

    /**
     * Function for encrypting data from stream and sending it into another stream
     * Function will get instance of cipher and initalize it
     * @param pass password for enecryption
     * @param itCount iteration count for turning password into key
     * @param is is a stream containg data for encryption
     * @param os is a target stream for encrypted data
     * @return byte length of decrypted data, -1 if error was encountered
     */
    int encryptDataStreamToStream(char [] pass,
					       int itCount,
					       InputStream is,
						OutputStream os) throws IOException;

    /**
     * Function for decrypting data from stream and sending it into another stream
     * @param pass password for decryption
     * @param is is a stream containg data in format native to this class
     * @param os is a target stream for decrypted data
     * @return byte length of decrypted data, -1 if error was encountered
     */
    int decryptDataStreamToStream(char [] pass,
						InputStream is,
						OutputStream os) throws IOException;


}
