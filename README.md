# Cryptest
learning java crypto functions

https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html

## Learned so far:

* CIPHER does the job of encrypting and decrypting
* CIPHER is created using getInstace and name of operation mode (algorithm for encryption, padding, hashing etc.) from: https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html
* CIPHER is initialized and accepts mode, key and parameters
* key can be generated (using generator) out of thin air (randomness source) or fabricated basing on some data (stored in key spec object)
* fabrication and generation is done by Factory or Generator, both are created using factory methods getInstance from respective classes, methods take 
* parameters are stored in param spec object, constructed using new, with arguments (for AES it is

There is such thing as defining 'provider' (which can specify how exactly things should be done) but it limits portability and can hurt performance


### For password based encryption there are classes and algorithm names with PBE prefix

* key spec and  parameter spec are in javax.crypto.spec https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/package-summary.html
* PBE key spec - what does it do? It takes password in char [] form, can also take salt and iteration count. <- it can be passed as an arguemnt to SecretKeyFactory generateSecret method to get SecretKey, that can be passed to Cipher init method.
* SecretKeySpec implements key, but PBEKeySpec does not, which makes sense since it doesn't contain any information about algorithm, it is just raw passphrase and some optional hashing parameters
* SecretKeyFactory needs to be created using SecretKeyFactory.getInstance(String algorithm)
* Where to find out what kind of parameters AES Cipher need? (Except examples?) - maybe in provider documentation? There is something called PKCS #5 https://tools.ietf.org/html/rfc2898#section-4.1
* Why oh why secret key factory doesn't need key param spec but cipher init does need?
 * Key param spec contains salt (10 random bytes?) and iteration count (1000 times)
 * maybe because Cipher needs to add this information to encrypted data in order to decrypt with the same parameters...
* For decryption pbe params are not needed for cipher, they are probably inferred from metada attached to encrypted data
* Seems that only decryption with the same cipher object works this way. After changing decryption object initialization complains on lack of IV. Probably need some additional parameter in constructor of PBEParameterSpec, meaning AlgorithmParameterSpec class https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/IvParameterSpec.htmlx
* For some reason it might be prudent to delete contents of passphrase and secret key variable?
* CipherInputStream can be used to decrypt/encrypt contents of the files

### How to include IV, salt and iteration count in encrypted message?
* 
* Maybe AEAD? AAD?
* ByteBuffer https://docs.oracle.com/javase/8/docs/api/java/nio/ByteBuffer.html can be used to convert primitive types into byte arrays and back. Despite the fact, that it has abstract methods it can be used, because it has subclasses (that themselves are not documented) https://community.oracle.com/thread/1210528
Class that has been actually used can be printed using (java.nio.ByteBuffer.allocate(1)).getClass().getName()

### Using separate keys encrypted using keyfiles
* Key wrapping
