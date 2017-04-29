import rsa
import random
import pyaes
import os
import secrets


AES_KEY_SIZE=128

def get_unique_keys(comparsion_results):
    unique_keys=[]
    for i in range(len(comparsion_results)):
        b,value=comparsion_results[i]
        unique_keys.append(b)
    return list(set(unique_keys))

def generate_rsa_keys(function_outcomes,unique_bs):
    rsa_unique_keys=[]
    rsa_public_key_containers=[]
    rsa_private_key_containers=[]
    
    for j in range(len(unique_bs)):
        public, private = rsa.newkeys(512)
        rsa_unique_keys.append([unique_bs[j],public,private])
    
    for i in range(len(function_outcomes)):
        b,value=function_outcomes[i]
        for k in range(len(rsa_unique_keys)):
            if b==rsa_unique_keys[k][0]:
                rsa_public_key_containers.append([b,rsa_unique_keys[k][1]])
                rsa_private_key_containers.append(rsa_unique_keys[k][2])
        
        
    return rsa_public_key_containers,rsa_private_key_containers

def generate_aes_key():
    key = secrets.token_bytes(int(AES_KEY_SIZE/8))
    
    return key
    

def encrypt_aes_key_using_rsa(aes_key,b,rsa_public_keys,key_counts):
    encrypted_aes_keys=[]
    rsa_public_key=rsa_public_keys[0][1]
    for j in range(len(rsa_public_keys)):
        if b==rsa_public_keys[j][0]:
            rsa_public_key=rsa_public_keys[j][1]
    
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
        ciphertext = aes.encrypt(str(function_outcomes[i][1]))
        encrypted_function_outcomes.append(ciphertext)

    return encrypted_function_outcomes
        
def decrypt_function_outcome_using_aes(encrypted_function_outcomes,aes_key):
    decrypted_function_outcomes=[]
    for i in range(len(encrypted_function_outcomes)):
        aes = pyaes.AESModeOfOperationCTR(aes_key)
        plaintext = aes.decrypt(encrypted_function_outcomes[i])
        decrypted_function_outcomes.append(plaintext)

    return decrypted_function_outcomes

class RECEIVER:
    def __init__(self, b):
        self.__b=b
        self.__aes_key=aes_key=generate_aes_key()
        
    def send_encrypted_aes_keys(self,rsa_public_key_containers,key_counts):
        return encrypt_aes_key_using_rsa(self.__aes_key,self.__b,rsa_public_key_containers,key_counts)
    
    def decrypt_function_results(self,encrypted_function_outcomes):
        decrypted_function_outcomes=decrypt_function_outcome_using_aes(encrypted_function_outcomes,self.__aes_key)
        print(decrypted_function_outcomes)
        
class SENDER:
    def __init__(self,function_outcomes):
        self.rsa_public_key_containers=[]
        self.__rsa_private_key_containers=[]
        self.rsa_public_key_containers,self.__rsa_private_key_containers=generate_rsa_keys(function_outcomes,unique_bs)
        self.__function_outcomes=function_outcomes
    
    def send_rsa_public_keys(self):
        return self.rsa_public_key_containers
    
    def send_encrypted_results(self,encrypted_aes_keys):
        decrypted_aes_keys=decrypt_aes_key_using_rsa(encrypted_aes_keys,self.__rsa_private_key_containers)
        return encrypt_function_outcome_using_aes(self.__function_outcomes,decrypted_aes_keys)
        
        
        
        
        
if __name__ == '__main__':
    
    #containers
    rsa_public_key_containers=[]
    rsa_private_key_containers=[]
    b='a'
    aes_key=0
    iv=0
    encrypted_aes_keys=[]
    decrypted_aes_keys=[]
    encrypted_function_outcomes=[]
    decrypted_function_outcomes=[]
    unique_bs=[]
    
    #dummy data 10 results 
    function_outcomes=[('a',1),('a',0),('a',1),('b',2),('b',2),('b',1),('b',0),('b',0),('c',0),('c',0),('c',0),('c',0),('c',0)]
    
    #get unique bs
    #print(get_unique_keys(function_outcomes))
    unique_bs=get_unique_keys(function_outcomes)
    
    #generate RSA keys for 10 outcomes
    rsa_public_key_containers,rsa_private_key_containers=generate_rsa_keys(function_outcomes,unique_bs)
    #print(rsa_public_key_containers)
    
    #generate AES key
    aes_key=generate_aes_key()
    
    #u = k^eb (mod nb) encrypt AES keys using RSA public keys
    encrypted_aes_keys=encrypt_aes_key_using_rsa(aes_key,b,rsa_public_key_containers,len(function_outcomes))
    
    
    #k0 = u^d0 (mod n0)
    #k1 = u^d1 (mod n1)
    #decrypt AES keys using RSA private keys
    decrypted_aes_keys=decrypt_aes_key_using_rsa(encrypted_aes_keys,rsa_private_key_containers)
    

    #encrypt comparison results using AES keys
    encrypted_function_outcomes=encrypt_function_outcome_using_aes(function_outcomes,decrypted_aes_keys)
    
    
    #decrypt comparison results using AES keys
    decrypted_function_outcomes=decrypt_function_outcome_using_aes(encrypted_function_outcomes,aes_key)
    
    
    
    print (decrypted_function_outcomes)
    #for i in range(len(decrypted_function_outcomes)):
        #print(decrypted_function_outcomes[i])
        
    
    
    
    
    
    
    #Two parties   
    senderA=SENDER(function_outcomes)
    
    receiverA=RECEIVER(b)
    
    rsa_public_key_containers=senderA.send_rsa_public_keys()
    
    #print(rsa_public_key_containers)
    
    encrypted_aes_keys=receiverA.send_encrypted_aes_keys(rsa_public_key_containers,len(rsa_public_key_containers))
    
    encrypted_function_outcomes=senderA.send_encrypted_results(encrypted_aes_keys)
    
    receiverA.decrypt_function_results(encrypted_function_outcomes)