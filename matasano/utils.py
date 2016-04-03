import binascii
from Crypto import Random
from Crypto.Cipher import AES
import itertools
from math import ceil
import string

def hex_to_b64(hex_string):
    return binascii.b2a_base64(hex_to_raw(hex_string)).rstrip()

def b64_to_raw(b64_string):
    return binascii.a2b_base64(b64_string)

def raw_to_hex(raw):
    return ''.join(['{:02x}'.format(b) for b in raw])

def raw_to_bin(raw):
    return ''.join(['{:b}'.format(b) for b in raw])

def raw_to_ascii(raw):
    return ''.join([chr(b) for b in raw])

def hex_to_raw(hex_string):
    return binascii.unhexlify(hex_string)

def ascii_to_raw(ascii_string):
    # If ascii_string is actually a string, it will be joined
    # until it is no longer a list, meaning if it is a list of lists of strings
    # it will correctly be converted into a string USEFUL IN CHALLENGE 6
    while isinstance(ascii_string, list):
        ascii_string = ''.join([element for element in ascii_string])
    return bytes(ascii_string, 'ascii')

def fixed_xor(msg, key):
    msg, key = list(msg), list(key)
    if len(msg) != len(key):
        raise ValueError("Msg and key lenghts do not match. msg {}, key {}".format(len(msg),len(key)))
    return bytes([msg[i] ^ key[i] for i in range(0,len(msg))])

def score_plaintext(plaintext):
    ETAOIN = 'ETAOINSHRDLCUMWFGYPBVKJXQZ '
    counter = 0
    for letter in plaintext:
        if letter.upper() in ETAOIN:
            counter += 1
    return counter

def single_char_xor_bruteforce(ciphertext):
    keys = list(string.printable)
    l = [{
        'key': key,
        'msg': raw_to_ascii(repeating_key_xor(ciphertext, ascii_to_raw(key))),
        'score': score_plaintext(raw_to_ascii(repeating_key_xor(ciphertext, ascii_to_raw(key)))),
    } for key in keys]
    return sorted(l, key=lambda x: x['score'], reverse=True)

def repeating_key_xor(msg, key):
    key = (ceil(len(msg)/len(key))*key)[:len(msg)]
    return fixed_xor(msg, key)

def hamming_dist(raw1, raw2):
    return sum([bin(l).count('1') for l in fixed_xor(raw1, raw2)])

def break_raw_into_chunks(raw, chunksize):
    blocks = [raw[i:i+chunksize] for i in range(0,len(raw),chunksize)]
    # Asserting joining parts of blocks is equal to original ciphertext
    assert(''.join([raw_to_ascii(i) for i in blocks]) == raw_to_ascii(raw))
    assert(len(blocks) == ceil(len(raw)/chunksize))
    return blocks

def transpose_blocks(blocks):
    return [block for block in itertools.zip_longest(*blocks, fillvalue=0)]

def aes_cbc_encrypt(key, msg):
    block_size = len(key)
    padding = block_size - (len(msg) % block_size)
    msg = msg + chr(padding) * padding
    iv = Random.new().read(block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(msg)

def aes_cbc_decrypt(key, cpt):
    block_size = len(key)
    iv, cpt = cpt[:block_size], cpt[block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.decrypt(cpt)
    return msg[:-msg[-1]]