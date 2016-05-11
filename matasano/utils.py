import binascii
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
import itertools
from math import ceil
import string
import struct

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

def hex_to_decimal(hex_string):
    return int(hex_string, 16)

def big_int_to_raw(big_int):
    return struct.pack(">I", big_int)

def raw_to_int(raw):
    return int.from_bytes(ip_bytes, byteorder='big')

def ascii_to_raw(ascii_string):
    # If ascii_string is aa list it will be joined until it is no longer, e.g.
    # a list of lists of strings will correctly be converted into a string USEFUL IN CHALLENGE 6
    while isinstance(ascii_string, list):
        ascii_string = ''.join([element for element in ascii_string])
    if isinstance(ascii_string, bytes):
        return ascii_string
    return bytes(ascii_string, 'utf-8')

def list_of_int_to_bytes(list_of_ints):
    return bytes(list_of_ints)  # more of a reminder than an actual useful method

def fixed_xor(msg, key):
    msg, key = list(msg), list(key)
    if len(msg) != len(key):
        raise ValueError("Msg and key lenghts do not match. msg {}, key {}".format(len(msg),len(key)))
    return bytes([msg[i] ^ key[i] for i in range(len(msg))])

def repeating_char_xor(msg, key_char):
    return fixed_xor(msg, [key_char for _ in range(len(msg))])

def repeating_key_xor(msg, key):
    key = (ceil(len(msg)/len(key))*key)[:len(msg)]
    return fixed_xor(msg, key)

def score_plaintext(plaintext, strict=False):
    ETAOIN = 'etaoinshrdlcumwfgypbvkjxqzETAOINSHRDLCUMWFGYPBVKJXQZ 1234567890!"\'#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n\r'
    counter = 0
    for letter in plaintext:
        if letter.upper() in ETAOIN:
            counter += len(ETAOIN) - ETAOIN.index(letter.upper())
        else:
            counter -= len(ETAOIN)  # to punish plain texts with non printable chars
    return counter/len(plaintext)

def single_char_xor_bruteforce(ciphertext):
    l = {key:score_plaintext(raw_to_ascii(repeating_char_xor(ciphertext, key))) for key in range(255)}
    return sorted(l.items(), key=lambda x: x[1], reverse=True)[0][0]

def hamming_dist(raw1, raw2):
    return sum([bin(l).count('1') for l in fixed_xor(raw1, raw2)])

def break_raw_into_chunks(raw, chunksize):
    return [raw[i:i+chunksize] for i in range(0,len(raw),chunksize)]

def transpose_blocks(blocks):
    # Gets the nth element of every block and creates a new block with them, e/g/
    # transpose_blocks([[1,2,3],[1,2,3],[1,2,3]]) == [[1,1,1],[2,2,2],[3,3,3]]
    return [block for block in itertools.zip_longest(*blocks, fillvalue=0)]

def discover_block_size(oracle):
    initial_len = len(oracle(''))
    for i in range(100):
        new_len = len(oracle('A'*i))
        if new_len - initial_len > 0:
            return new_len - initial_len

# Below AES methods with PKCS#7 padding scheme

def pad_with_pkcs7(msg, block_size=16):
    msg = ascii_to_raw(msg)
    padding = block_size - (len(msg) % block_size)
    msg = msg + bytes(chr(padding) * padding, 'ascii')
    return msg

def unpad_with_pkcs7(padded_plaintext):
    padded_plaintext = ascii_to_raw(padded_plaintext)
    last_byte = padded_plaintext[-1]
    pad = padded_plaintext[-last_byte:]
    if len(pad) != last_byte or [c for c in pad if c != last_byte]:
        raise ValueError("Bad padding. Last_byte = {}".format(hex(last_byte)))

    return padded_plaintext[:-last_byte]

def aes_ecb_encrypt(key, msg):
    block_size = len(key)
    msg = pad_with_pkcs7(msg)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(msg)

def aes_ecb_decrypt(key, cpt):
    block_size = len(key)
    cipher = AES.new(key, AES.MODE_ECB)
    msg = cipher.decrypt(cpt)
    return unpad_with_pkcs7(msg)

def aes_cbc_encrypt(key, msg, iv=''):
    block_size = len(key)
    msg = pad_with_pkcs7(msg)
    iv = iv or Random.new().read(block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(msg)

def aes_cbc_decrypt(key, cpt):
    block_size = len(key)
    iv, cpt = cpt[:block_size], cpt[block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.decrypt(cpt)
    return unpad_with_pkcs7(msg)

def detect_aes_block_cipher_mode(oracle, block_size):
        blocks = break_raw_into_chunks(oracle('A'*block_size*3), block_size)
        return 'ECB' if sum([1 for b1, b2 in list(itertools.combinations(blocks,2)) if b1==b2]) > 0 else 'CBC'

def aes_ecb_find_secret_appended_text(oracle, block_size):
    # finds max size of prepended text, give or take padding
    cpt = break_raw_into_chunks(oracle('A' * block_size * 20), block_size)
    for i, chunk in enumerate(cpt):
        if chunk == cpt[i+1]:  # If True, prepended finishes between i-1 and i
            max_size_of_prepended_text = i*block_size
            break

    # brute forces the appended text one character at a time
    for i in range(0, block_size):
        padding = 'A'*i
        my_input = 'A' * (block_size * 11)
        secret_append = ''

        try:
            while my_input:
                my_input = my_input[:-1]
                d = {oracle(padding + my_input + secret_append + l)[max_size_of_prepended_text+160:max_size_of_prepended_text+176]:l for l in string.printable}
                secret_append += d[oracle(padding + my_input)[max_size_of_prepended_text+160:max_size_of_prepended_text+176]]
        except KeyError:
            if secret_append:
                return ascii_to_raw(secret_append)

def aes_ctr_encrypt(key, msg, counter):
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(msg)

def aes_ctr_randomiv_encrypt(key, msg):
    counter = Counter.new(8*16, initial_value = int.from_bytes(Random.new().read(16), 'big'))
    iv = bytes.fromhex(hex(counter.next_value())[2:])
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return iv + cipher.decrypt(msg)

def aes_ctr_randomiv_decrypt(cpt):
    counter = Counter.new(8*16, initial_value = int.from_bytes(cpt[:16],'big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(cpt[16:])