import rsa
import pyaes
import os
import OT
from random import *
# A 256 bit (32 byte) key
key = os.urandom(16)
#print key


print("Assuming Auctioneer and all biders are authenticated\n")
(public_A, private_A) = rsa.newkeys(512)
(public_B, private_B) = rsa.newkeys(512)
(public_C, private_C) = rsa.newkeys(512)
print("Sending bidder A,B,C's public RSA keys to the auctioneet\n")

print("Bidder A initializes the function table f(x,y,z)\n")
func_x_y_z=[]
aes = pyaes.AESModeOfOperationCTR(key)
for i in range (32):
	for j in range(32):
		a=aes.encrypt(str(i))
		b=aes.encrypt(str(j))
		func_x_y_z.append((a,b))

A_prince=randint(0,31)
print( "The Auctioneer's key is used to encrypt all entries in the function table\n")

print("Using OT to present the function table to bidder B\n")

unique_bs=OT.get_unique_keys(func_x_y_z)
print("With Y chosen, bidder B will present the function table to C via OT")
#containers
B_price=randint(0,31)
rsa_public_key_containers=[]
rsa_private_key_containers=[]
aes_key=0
iv=0
encrypted_aes_keys=[]
decrypted_aes_keys=[]
encrypted_function_outcomes=[]
decrypted_function_outcomes=[]
unique_bs=[]
unique_bs=OT.get_unique_keys(func_x_y_z)
    
rsa_public_key_containers,rsa_private_key_containers=OT.generate_rsa_keys(func_x_y_z,unique_bs)
aes_key=OT.generate_aes_key()
encrypted_aes_keys=OT.encrypt_aes_key_using_rsa(aes_key,aes.encrypt(B_price),rsa_public_key_containers,len(func_x_y_z))
decrypted_aes_keys=OT.decrypt_aes_key_using_rsa(encrypted_aes_keys,rsa_private_key_containers)
encrypted_function_outcomes=OT.encrypt_function_outcome_using_aes(func_x_y_z,decrypted_aes_keys)
decrypted_function_outcomes=OT.decrypt_function_outcome_using_aes(encrypted_function_outcomes,aes_key)

senderA=OT.SENDER(func_x_y_z)
# B_prince=randint(0,31)

receiverA=OT.RECEIVER(aes.encrypt(B_price))
    
rsa_public_key_containers=senderA.send_rsa_public_keys()
    
print(rsa_public_key_containers)
    
encrypted_aes_keys=receiverA.send_encrypted_aes_keys(rsa_public_key_containers,len(rsa_public_key_containers))
    
encrypted_function_outcomes=senderA.send_encrypted_results(encrypted_aes_keys)

receiverA.decrypt_function_results(encrypted_function_outcomes)

# problem here: because we are using 2^5 options for each bidder, the OT with rsa encryptionbecause 
# too much for computation and the program runs a while. 

C_price=randint(0,31)

func_y_z=[]

for k in range(len(encrypted_function_outcomes)):
	if encrypted_function_outcomes[k][0]==aes.encrypt(C_price):
		for j in range(32):
			func_y_z.append(encrypted_function_outcomes[k][j])





# SENDING TO 
#containers
rsa_public_key_containers_c=[]
rsa_private_key_containers_c=[]
aes_key_c=0
# iv=0
encrypted_aes_keys_c=[]
decrypted_aes_keys_c=[]
encrypted_function_outcomes_c=[]
decrypted_function_outcomes_c=[]
unique_bs_c=[]
unique_bs_c=OT.get_unique_keys(func_y_z)
    
rsa_public_key_containers_c,rsa_private_key_containers_c=OT.generate_rsa_keys(func_y_z,unique_bs_c)
aes_key_c=OT.generate_aes_key()
encrypted_aes_keys_c_c=OT.encrypt_aes_key_using_rsa(aes_key_c,aes.encrypt(C_price),rsa_public_key_containers_c,len(func_y_z))
decrypted_aes_keys_c=OT.decrypt_aes_key_using_rsa(encrypted_aes_keys_c,rsa_private_key_containers_c)
encrypted_function_outcomes_c=OT.encrypt_function_outcome_using_aes(func_y_z,decrypted_aes_keys_c)
decrypted_function_outcomes_c=OT.decrypt_function_outcome_using_aes(encrypted_function_outcomes_c,aes_key_c)

senderB=OT.SENDER(func_y_z)

receiverC=OT.RECEIVER(aes.encrypt(C_price))
    
rsa_public_key_containers_c=senderB.send_rsa_public_keys()
    
encrypted_aes_keys_c=receiverC.send_encrypted_aes_keys(rsa_public_key_containers_c,len(rsa_public_key_containers_c))
    
encrypted_function_outcomes_c=senderB.send_encrypted_results(encrypted_aes_keys_c)

receiverC.decrypt_function_results(encrypted_function_outcomes_c)



print("The Auctioneer receives the encrypted results and compare them")

compare=[]

for q in range(len(encrypted_function_outcomes_c)):
	compare.append((int(aes.decrypt(encrypted_function_outcomes_c[q][0])),int(aes.decrypt(encrypted_function_outcomes_c[q][1]))))

maxi=compare[0][0]
for count in range (len(compare)):
	if compare[count][0]>maxi:
		maxi=compare[count][0]


print ("The auctioneer broadcast the highest bid price")
print (maxi)

# (bob_pub, bob_priv) = rsa.newkeys(512)
# (bob_pub1, bob_priv1) = rsa.newkeys(512)

# # print( bob_pub)


# message = 'hello Bob!'
# # print(message)
# # print( bob_pub)
# # print( bob_priv)

# crypto = rsa.encrypt(key, bob_pub)

# message = rsa.decrypt(crypto, bob_priv)

# # print(message)

