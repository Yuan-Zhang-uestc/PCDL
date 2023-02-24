from binascii import hexlify
from binascii import unhexlify
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
import random
import os, codecs
import datetime
digits = 64 #32 bytes

def modExp(a, exp, mod):
    fx = 1
    while exp > 0:
    	if (exp & 1) == 1:
    		fx = fx * a % mod
    	a = (a * a) % mod
    	exp = exp >> 1
    return fx

#modExp(x,a,p)
hex_a = codecs.encode(os.urandom(digits), 'hex').decode()
hex_p = codecs.encode(os.urandom(digits), 'hex').decode()


a = int(hex_a,16)
p = int(hex_p,16)



def Share(key):
    key = get_random_bytes(32)
    print("share secret: ", hexlify(key))
    shares = Shamir.split(10, 20, key)

    for idx, share in shares:
        print ("Index %d: %s" % (idx, hexlify(share)))

    #print("generate the shared key: ", (end-start).total_seconds())
    return shares



#key1 = int(key.hex(),16)
#result = modExp(a, key1, p)
#print("compution result:", result)

#print("compute the modExp: ", (end-start).total_seconds())

#start = datetime.datetime.now()

key = get_random_bytes(16)
print("share secret: ", hexlify(key))
shares = Shamir.split(10, 20, key)

shares1 = []
shares1.append(shares[1])
shares1.append(shares[2])
shares1.append(shares[3])
shares1.append(shares[4])
shares1.append(shares[5])
shares1.append(shares[6])
shares1.append(shares[7])
shares1.append(shares[8])
shares1.append(shares[9])
shares1.append(shares[10])

def Recover(shares1):
    key_recover = Shamir.combine(shares1)
    print("recovered share key: ", hexlify(key_recover))
    #end = datetime.datetime.now()
    #print("recover the share key: ", (end-start).total_seconds())

#x=random.randint(10e300, 10e301)
#print(hex(x))

