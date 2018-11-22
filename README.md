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
* Where to find out what kind of parameters AES Cipher need? (Except examples?) - maybe in provider documentation?