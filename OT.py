import rsa
import random
import pyaes
import os
import secrets


AES_KEY_SIZE=128

def generate_rsa_keys(key_counts):
    rsa_public_key_containers=[]
    rsa_private_key_containers=[]
    
    for i in range(key_counts):
        public, private = rsa.newkeys(512)
        rsa_public_key_containers.append(public)
        rsa_private_key_containers.append(private)
        
        
    return rsa_public_key_containers,rsa_private_key_containers

def generate_aes_key():
    key = secrets.token_bytes(int(AES_KEY_SIZE/8))
    
    return key
    

def encrypt_aes_key_using_rsa(aes_key,rsa_public_key,key_counts):
    encrypted_aes_keys=[]
    
    for i in range(key_counts):
        encrypted_aes_key=rsa.encrypt(aes_key,rsa_public_key)
        encrypted_aes_keys.append(encrypted_aes_key)
    return encrypted_aes_keys
    
def decrypt_aes_key_using_rsa(encrypted_aes_keys,rsa_private_keys):
    decrypted_aes_keys=[]
    for i in range(len(rsa_private_keys)):
        try:
            decrypted_aes_key=rsa.decrypt(encrypted_aes_keys[i],rsa_private_keys[i])
        except:
            decrypted_aes_key=key = secrets.token_bytes(int(AES_KEY_SIZE/8))
        decrypted_aes_keys.append(decrypted_aes_key)

    return decrypted_aes_keys

def encrypt_function_outcome_using_aes(function_outcomes,aes_keys):
    encrypted_function_outcomes=[]
    for i in range(len(aes_keys)):
        aes = pyaes.AESModeOfOperationCTR(aes_keys[i])
        ciphertext = aes.encrypt(str(function_outcomes[i]))
        encrypted_function_outcomes.append(ciphertext)

    return encrypted_function_outcomes
        
def decrypt_function_outcome_using_aes(encrypted_function_outcomes,aes_key):
    decrypted_function_outcomes=[]
    for i in range(len(encrypted_function_outcomes)):
        aes = pyaes.AESModeOfOperationCTR(aes_key)
        plaintext = aes.decrypt(encrypted_function_outcomes[i])
        decrypted_function_outcomes.append(plaintext)

    return decrypted_function_outcomes
        
if __name__ == '__main__':
    
    #containers
    rsa_public_key_containers=[]
    rsa_private_key_containers=[]
    b=10
    aes_key=0
    iv=0
    encrypted_aes_keys=[]
    decrypted_aes_keys=[]
    encrypted_function_outcomes=[]
    decrypted_function_outcomes=[]
    
    #dummy data 10 results 
    function_outcomes=[0,0,0,0,0,0,1,1,1,1,0,1,1]
    
    #generate RSA keys for 10 outcomes
    rsa_public_key_containers,rsa_private_key_containers=generate_rsa_keys(len(function_outcomes))
    
    #generate AES key
    aes_key=generate_aes_key()
    
    #u = k^eb (mod nb) encrypt AES keys using RSA public keys
    encrypted_aes_keys=encrypt_aes_key_using_rsa(aes_key,rsa_public_key_containers[b],len(function_outcomes))
    
    
    #k0 = u^d0 (mod n0)
    #k1 = u^d1 (mod n1)
    #decrypt AES keys using RSA private keys
    decrypted_aes_keys=decrypt_aes_key_using_rsa(encrypted_aes_keys,rsa_private_key_containers)
    

    #encrypt comparison results using AES keys
    encrypted_function_outcomes=encrypt_function_outcome_using_aes(function_outcomes,decrypted_aes_keys)
    
    
    #decrypt comparison results using AES keys
    decrypted_function_outcomes=decrypt_function_outcome_using_aes(encrypted_function_outcomes,aes_key)
    
    
    
    print (decrypted_function_outcomes)
    for i in range(len(decrypted_function_outcomes)):
        print(decrypted_function_outcomes[i])