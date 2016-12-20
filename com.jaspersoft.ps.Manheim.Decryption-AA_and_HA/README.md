\# com.jaspersoft.ps.Manheim.Decryption
Manheim Encryption

This branch (aa and ah) add those attributes.

See the additional parameters added.. pa8 and p9

Right now I added these for all user types. They will be blank for some.
If they need to be MISSING for some, then we can remove that code from them..

E and EC were the only areas changed, but I passed the token into all methods for conformity.



First Manheim will create a token.

This token is something like 

pp=u=jason|o=Manheim1|r=ROLE_ADMIN|pa1=1234|pa2=234

or really pp=<token>

debug code exists where you can see in the code that you can also send in 
pp=u=cus for a customer login (I generate the token myself)
OR
pp=u=emp for an employee login

where 
u=username
o=organization
r=Role(s) comma separated
pa(x)=user parameters added to user

This will be encrypted using 
 http://www.java2s.com/Code/Java/Security/EncryptionanddecryptionwithAESECBPKCS7Padding.htm 
 
The class Cypher (sic) in jar com.jaspersoft.ps.Manheim.Decrypt.jar is then run which decrypts the pp (token) and goes to the 
endpoint(s) to get the user information.....

Right now that is looking like a JDBC connection directly to Oracle, but we shall see.

*To install:

1. You need to upgrade the encryption for Java on the machine. This was implemented by the web components team.
http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html

2. You need the two binaries to be placed into the web-inf/lib of the jasperserver installation
https://www.dropbox.com/s/7ngdwrkhq7upb1z/com.jaspersoft.ps.Manheim.Decryption.jar?dl=0
https://www.dropbox.com/s/mejbyu9k17r2z5o/jaspersoft-token-service-1.0.jar?dl=0

3. You need to add the following configuration to WEB-INF
https://www.dropbox.com/s/oyql8vfvvc13jtj/applicationContext-externalAuth-preAuth-mt.xml?dl=0

4. restart tomcat to see changes.