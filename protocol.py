#!/usr/bin/env python3

from bitarray import bitarray
import secrets

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def init_fernet_encryption():
	# Lets roll our own encryption... Lol jk
	return Fernet(Fernet.generate_key())
	


def max_bidder(x, y, z):
	if x >= y and x >= z:
		return bitarray('00')
	elif y >= x and y >= z:
		return bitarray('01')
	else:
		return bitarray('10')
def second_bidder(x, y, z):
	if x >= y and x <= z:
		return bitfield(x, 10)
	elif y >= x and y <= z:
		return bitfield(y, 10)
	else:
		return bitfield(z, 10)

def gen_function_table_max(bid, key):
	array = []
	for i in range(0, 2**10):
		array.append(bitarray())
	
	for y in range(0, 2**10):
		for z in range(0, 2**10):
			array[y].extend(max_bidder(bid, y, z) ^ key)
	return array

def gen_function_table_second(bid, key):
	array = []
	for i in range(0, 2**10):
		array.append(bitarray())
	
	for y in range(0, 2**10):
		for z in range(0, 2**10):
			array[y].extend(max_bidder(bid, y, z) ^ key)
	return array


# Code for converting int to bitarray shamelessly stolen from stackoverflow
# http://stackoverflow.com/questions/10321978/integer-to-bitfield-as-a-list
# And then modified for my purposes into something completely different...
def bitfield(n, bits):
	# This abomination just makes sure we get exactly n bits from the number, by converting
	# to a binary string, chopping off the '0b', grabbing the last (bits) bits, and then left-filling
	# with zeroes if the result is less than (bits) bits. 
	return bitarray(bin(n)[2:][-bits:].zfill(bits))

# Also taken from
def ceildiv(a, b):
    return -(-a // b)

connections = {}

def send_to_party(party, msg):
	# Acces global dict of connections
	# Encrypt using appropriate symmetric key exchanged via RSA authentication
	# Send the message. Should be pickled python object, using max compression (to fit the fucking giant function tables)

def AES_Encrypt(msg, key):
	# Encrypts bitarray objects, must have multiple of 8 bits.
	backend = default_backend()
	cipher = Cipher(algorithms.AES(int(key.to01(), 2)), modes.CTR(b'0'), backend=backend)
	encryptor = cipher.encryptor()
	ct = encryptor.update(msg.tobytes()) + encryptor.finalize()
	return bitarray(ct)
	
def AES_Decrypt(msg, key):
	backend = default_backend()
	cipher = Cipher(algorithms.AES(int(key.to01(), 2)), modes.CTR(b'0'), backend=backend)
	decryptor = cipher.decryptor()
	pt = decryptor.update(msg.tobytes()) + decryptor.finalize()
	return bitarray(pt)

def OT_to_party(party, msg):
	k = len(msg)
	private_keys = []
	for i in range(k):
		tmp_key = rsa.generate_private_key(
		    public_exponent=65537,
		    key_size=2048,
		    backend=default_backend()
		)
		private_keys.append(tmp_key)
	public_keys = [key.public_key() for key in private_keys]
	
	#Serialize public keys for transmission
	#TODO: Determine if this will be required for transmission?
	# public_keys_serialized = []
	# for key in public_keys:
	# 	tmp_key = public_key.public_bytes(
	# 	   encoding=serialization.Encoding.PEM,
	# 	   format=serialization.PublicFormat.SubjectPublicKeyInfo
	# 	)
	# 	public_keys_serialized.append(tmp_key)
	
	send_to_party(party, public_keys)
	# Key sent should be an AES key
	u = get_from_party(party)
	encrypted_options = []
	for i in range(len(private_keys)):
		tmp_key = private_keys[i].decrypt(
			u, padding.OAEP(
		         mgf=padding.MGF1(algorithm=hashes.SHA1()),
		         algorithm=hashes.SHA1(),
		         label=None
		     )
		)
		encrypted_options.append(AES_Encrypt(msg[i], tmp_key))
	send_to_party(party, encrypted_options)
	
def OT_from_party(party, option):
	public_keys = get_from_party(party)
	choice_key = public_keys[option]
	aes_key = secrets.randbits(32)
	u = choice_key.encrypt(
		aes_key, padding.OAEP(
	         mgf=padding.MGF1(algorithm=hashes.SHA1()),
	         algorithm=hashes.SHA1(),
	         label=None
	     )
	)
	send_to_party(party, u)
	encrypted_options = get_from_party(party)
	chosen_option = encrypted_options[option]
	return AES_Decrypt(chosen_option, aes_key)
	
	

def bidder_protocol(bid):
	#TODO: Decide bid based on starting price?
	#TODO: Setup networking with the other bidders and the auctioneer
	init_network_ids(receive_networking_from_auctioneer)
	
	# First, we'll be assigned a number by the auctioneer
	my_id = receive_id()
	# Probably convert to binary string here
	
	# send_to_bidder('id', msg)
	
	#TODO: Generate public/private keypair and send public to the auctioneer
	public_key, private_key = gen_RSA_keypair()
	send_to_party('11', public_key)
	
	
	# If we're the first bidder, we'll begin the MPC to determine the winner.
	if my_id == '00':
		
		# Need to encrypt each entry with a single key we can send to the auctioneer to prevent C from reading the result
		auc_key = bitfield(secrets.randbits(2), 2)
		
		function_table = gen_function_table_max(bid, auc_key)
		
		# 
		c_key = bitarray(secrets.token_bytes(ceildiv(len(function_table[0]), 8)))[:len(function_table[0])]
		# Function table is encrypted via OTP, which is kind of necessary for the problem
		# Need to be able to decrypt one individual entry all alone, so each entry in a row needs to be encrypted separately
		
		function_table = [row ^ c_key for row in function_table]
		
		# Ok, function table is created and encrypted
		#TODO: OT to party two
		OT_to_party('01', function_table)
		
		#Send party C the row key
		send_to_party('10', [c_key[i, i + 2] for i in range(0, len(c_key), 2)])
		
		#TODO: Then send key to auctioneer
		send_to_party('11', auc_key)
		
		#Next round, we compute the second highest price
		#TODO: Get public key of winner if we are the loser
		did_win = get_from_party('11')
		if did_win:
			pub_key = public_key
		else:
			pub_key = get_from_party('11')
		
		
		
		uniform_key = bitfield(secrets.randbits(10), 10)
		function_table = gen_function_table_second(bid, uniform_key)
		c_key = bitarray(secrets.token_bytes(ceildiv(len(function_table[0]), 8)))[:len(function_table[0])]
		OT_to_party('01', function_table)
		send_to_party('10', [c_key[i, i + 10] for i in range(0, len(c_key), 10)])
		
		# This time, we encrypt the uniform key with the public key and then broadcast to all bidders
		encrypted_key = rsa_encrypt(uniform_key, pub_key)
		send_to_party('01', encrypted_key)
		send_to_party('10', encrypted_key)
		
		# Recieve encrypted result
		encrypted_res = get_from_party('10')
		

	elif my_id == '01':
		#TODO: Wait on and recieve row of function table via oblivious transfer from 00
		table_row = OT_from_party('00', bid)
		# Split up our row into the new function table
		new_table = [table_row[i, i + 2] for i in range(0, len(table_row), 2)]
		
		#TODO: OT this to party 3
		OT_to_party('10', new_table)
		
		#Next round
		did_win = get_from_party('11')
		if did_win:
			pub_key = public_key
		else:
			pub_key = get_from_party('11')
		
		table_row = OT_from_party('00', bid)
		new_table = [table_row[i, i + 10] for i in range(0, len(table_row), 10)]
		OT_to_party('10', new_table)
		
		# Recieve encrypted key
		encrypted_key = get_from_party('00')
		
		# Recieve encrypted result
		encrypted_res = get_from_party('10')
		
		
	elif my_id == '10':
		winner = OT_from_party('01', bid)
		
		key = get_from_party('00')
		#TODO: Will need to make sure network code sends proper python objects
		
		#TODO: Send winner to auctioneer
		#TODO: If bid isn't an int, use encoding that is used for OT to make it an int
		send_to_party('11', winner ^ key[bid])
		
		#Next round
		did_win = get_from_party('11')
		if did_win:
			pub_key = public_key
		else:
			pub_key = get_from_party('11')
		
		second_highest = OT_from_party('01', bid)
		key = get_from_party('00')
		
		second_highest = second_highest ^ key
		
		# Recieve encrypted key
		encrypted_key = get_from_party('00')
		
		# Now encrypt with public key and broadcast...
		encrypted_res = rsa_encrypt(second_highest, pub_key)
		send_to_party('00', encrypted_res)
		send_to_party('01', encrypted_res)
		
	# Now, if we were the winner we can compute the price
	if did_win:
		key = rsa_decrypt(encrypted_key, private_key)
		result = rsa_decrypt(encrypted_res, private_key)
		result = result ^ key
		return result
	else:
		return 'lost'

		

def auctioneer_protocol():
	#TODO: First, define which connections correspond to which IDs
	init_network_ids(connections)
	
	send_to_party('00', '00')
	send_to_party('01', '01')
	send_to_party('10', '10')
	
	# Collect public keys from each party
	
	public_keys['00'] = get_from_party('00')
	public_keys['01'] = get_from_party('01')
	public_keys['10'] = get_from_party('10')
	
	# Recieve the auc_key from party a
	auc_key = get_from_party('00')
	winner = get_from_party('10') ^ auc_key
	
	#Oh, C and A encrypt the (uniform) key and price with the public key and broadcast the result!
	
	for party in ['00', '10']:
		if party == winner:
			send_to_party(party, True)
		else:
			send_to_party(party, False)
			send_to_party(party, public_keys[winner.to01()])
	# Now the auctioneer is done.
	return winner
	
	
	
	