import hashlib
from copy import deepcopy
from secrets import token_bytes

from ec import (G1FromBytes, G1Generator, G1Infinity, G2FromBytes, G2Generator,
                G2Infinity, JacobianPoint, default_ec, default_ec_twist, scalar_mult_jacobian,
                sign_Fq2, twist, untwist, y_for_x)
from fields import Fq, Fq2, Fq6, Fq12
from hash_to_field import hash_to_field
from hkdf import expand, extract
from op_swu_g2 import g2_map
from pairing import ate_pairing
from private_key import PrivateKey
from schemes import AugSchemeMPL
from PCDL_Setup import Share
from binascii import hexlify
from Crypto.Random import get_random_bytes
from Crypto.Protocol.SecretSharing import Shamir
from sympy import Function, Symbol, expand
from Crypto.Random.random import getrandbits
from Crypto.Util.number import getPrime
from schemes import core_aggregate_mpl

q = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB

import ec

G1Element = JacobianPoint
G2Element = JacobianPoint

ID = int.from_bytes(bytes([1, 2]), byteorder="big")
PWD = int.from_bytes(bytes([3, 1, 4, 1, 5, 9]), byteorder="big")

g1 = G1Generator()
g2 = G2Generator()

seed: bytes = bytes(
        [
            0,
            50,
            6,
            244,
            24,
            199,
            1,
            25,
            52,
            88,
            192,
            19,
            18,
            12,
            89,
            6,
            220,
            18,
            102,
            58,
            209,
            82,
            12,
            62,
            89,
            110,
            182,
            9,
            44,
            20,
            254,
            22,
        ]
    )


t = 10
n = 20
P = getPrime(256) 

all_sub_pk = []

all_sub_signature = []

all_ski = []

shares1 = []


def AS() -> JacobianPoint:

    val: bytes = bytes([1, 2, 3, 4, 5]) # ID pwd
    val_ = int.from_bytes(val, byteorder='big', signed=False)

    H_val_ = g2 * val_ * 12371928312 + g2 * val_ * 12903812903891023

    msk: PrivateKey = AugSchemeMPL.key_gen(seed)
    #r: PrivateKey = AugSchemeMPL.key_gen(seed)

    msk_value = msk.value
    print(msk_value)

    a = [0]
    x = Symbol('x')
    f = Function('f')(x)
    f = msk_value   #S为主密钥

    for i in range(1, t):
        a.append(getrandbits(16))
        f += pow(x, i) * a[i]


    si = msk_value
    for i in range(1, n+1):
        for j in range(1, t):
            si = si + a[j] * pow(i, j)
        all_ski.append(si%q)
        si = msk_value
        j = 1
    

    mpk =  g1 * msk_value
    cred = H_val_ * msk_value 

    for ski in all_ski:
        print (ski)
        pki = ski * g1
        all_sub_pk.append(pki)
        print(pki)

    return mpk, H_val_, cred

def genBlind() -> PrivateKey:
    r: PrivateKey = AugSchemeMPL.key_gen(seed)
    return r


def Blind(r: PrivateKey, hash: JacobianPoint) -> JacobianPoint:
    blindsignature = hash * r.value
    return blindsignature


def Keyservers(blindsignature: JacobianPoint):

    for ski in all_ski:
        pre = blindsignature * ski
        all_sub_signature.append(pre)
        #print(all_sub_signature)

    return 0


def ASVerify(r: PrivateKey, hash: JacobianPoint, mpk: JacobianPoint, blindsignature: JacobianPoint, cred: JacobianPoint):

    #for sub_pk, sub_signature in zip(all_sub_pk,all_sub_signature):
        #print(ate_pairing(g1, sub_signature) == ate_pairing(sub_pk, blindsignature))
    
    wi = [0, 1]
    l = 1
    j = 1
    for l in range(1, 11):
        for j in range(1, 11):
            if(l == j):
                continue
            else:
             wi[l] = wi[l] * j / (j - l)
        wi.append(1)

    S1 = 0
    for i in range(1,t+1):
        S1 += int(wi[i]) * all_ski[i-1]
    print(S1)

    cred = blindsignature * S1
    
    cred_1 = all_sub_signature[0]*int(wi[1])

    for i in range(2,t+1):
        b: JacobianPoint = all_sub_signature[i-1]
        cred_1 = cred_1 + b * int(wi[i])

    cred_1 = g2 * 0

    cred_1 = blindsignature * ((all_ski[0] * int(wi[1]))%q)

    for i in range(2, t+1):
        cred_1 = core_aggregate_mpl([cred_1, blindsignature * ((all_ski[i-1] * int(wi[i]))%q)])
        
        #cred_1 + hash * ((all_ski[i-1] * r.value * int(wi[i]))%q)

        #core_aggregate_mpl()

    ok: bool = ate_pairing(g1, cred) == ate_pairing(mpk, blindsignature)

    print(ok)

    return ok



result = AS()

rr = genBlind()

blindsignature = Blind(rr, result[1])

Keyservers(blindsignature)

ASVerify(rr, result[1], result[0], result[2], blindsignature)
    
