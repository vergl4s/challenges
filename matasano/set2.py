#!/usr/bin/env python3
from Crypto import Random
from Crypto.Cipher import AES
import itertools

from utils import *

def challenge9():
    
    def encrypt(msg, key, block_size=16):
        # block_size = len(key)
        padding = block_size - (len(msg) % block_size)
        msg = msg + chr(padding) * padding
        iv = Random.new().read(block_size)
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        return iv + encryptor.encrypt(msg)

    def decrypt(cpt, key, block_size=16):
        # block_size = len(key)
        iv = cpt[:block_size]
        cpt = cpt[block_size:]
        encryptor = AES.new(key, AES.MODE_CBC, iv)
        msg = encryptor.decrypt(cpt)
        return msg[:-msg[-1]]

    # return decrypt(hex_to_raw('4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'), hex_to_raw('140b41b22a29beb4061bda66b6747e14'))
    # return decrypt(hex_to_raw('5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'), hex_to_raw('140b41b22a29beb4061bda66b6747e14'))
    return decrypt(hex_to_raw('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'), hex_to_raw('36f18357be4dbd77f050515c73fcf9f2'))

if __name__ == '__main__':
    print(challenge9())
