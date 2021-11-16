# trojan_aes_obfuscated
This is a POC to show:

- a shellcode for a trojan, which performs a fork, making the child execute a reverse shell and the parent execute the other part of the program seamlessly;
- a basic polymorphism: the shellcode is AES-encrypted in ECB mode with PKCS7 padding, so the victim C program to be modified has the encrypted shellcode, the key and the procedure to decrypt it and to jump to it.

The rationale is that to change the trojan's signature, it's enough to encrypt the shellcode with a new key and change the buffer and the key in the program. The procedure to decrypt it and to jump to it ("engine") could be the target for a signature, but it can easily lead to false positives. </br> </br>
The complete POC is in the folder /integration_poc. 
