import binascii
import itertools
import hashlib
from math import ceil
from os import urandom
import random
import string
import struct
import time
import urllib.request

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import getPrime as primegen

def raw_to_b64(raw):
    return binascii.b2a_base64(raw).rstrip()

def b64_to_raw(b64_string):
    return binascii.a2b_base64(b64_string)

def raw_to_hex(raw):
    return binascii.hexlify(bytes(raw)).decode('utf-8')
    # return ''.join(['{:02x}'.format(b) for b in raw])

def raw_to_bin(raw):
    return ''.join(['{:b}'.format(b) for b in raw])

def raw_to_ascii(raw):
    return ''.join([chr(b) for b in raw])

def hex_to_raw(hex_string):
    return binascii.unhexlify(hex_string)

def hex_to_decimal(hex_string):
    return int(hex_string, 16)

def int_to_raw(integer):
    # return struct.pack(">I", big_int)  # left for reference
    return integer.to_bytes(integer.bit_length()//8+1, byteorder='big')

def raw_to_int(raw):
    return int.from_bytes(raw, byteorder='big')

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

def parse_unicode_str(str_w_unicode_chars):
    # e.g. "Rollin' in my 5.\x8c\xf6\xe1\xb6uT\x8e_bby"
    import codecs
    return codecs.escape_decode(str_w_unicode_chars)[0]

####################################
#           Common methods         #
####################################

def xor(msg, key):
    msg, key = list(msg), list(key)
    if len(msg) != len(key):
        raise ValueError("Msg and key lenghts do not match. msg {}, key {}".format(len(msg),len(key)))
    return bytes([msg[i] ^ key[i] for i in range(len(msg))])

def repeating_char_xor(msg, key_char):
    return xor(msg, [key_char for _ in range(len(msg))])

def repeating_key_xor(msg, key):
    key = (ceil(len(msg)/len(key))*key)[:len(msg)]
    return xor(msg, key)

def score_plaintext(plaintext, strict=False):
    ETAOIN = 'ETAOINSHRDLCUMWFGYPBVKJXQZ 1234567890!"\'#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n\r'
    counter = 0
    for letter in plaintext:
        if letter.upper() in ETAOIN:
            counter += len(ETAOIN) - ETAOIN.index(letter.upper())
        else:
            counter -= len(ETAOIN)  # to punish plain texts with non printable chars
    return counter/len(plaintext)

def single_char_xor_bruteforce(ciphertext):
    l = {key:score_plaintext(raw_to_ascii(repeating_char_xor(ciphertext, key))) for key in range(256)}
    return sorted(l.items(), key=lambda x: x[1], reverse=True)[0][0]

def hamming_dist(raw1, raw2):
    return sum([bin(l).count('1') for l in xor(raw1, raw2)])

def break_raw_into_chunks(raw, chunksize):
    return [raw[i:i+chunksize] for i in range(0,len(raw),chunksize)]

def transpose_blocks(blocks):
    # Gets the nth element of every block and creates a new block with them, e/g/
    # transpose_blocks([[1,2,3],[1,2,3],[1,2,3]]) == [[1,1,1],[2,2,2],[3,3,3]]
    return [block for block in itertools.zip_longest(*blocks, fillvalue=0)]

def targeted_bit_flipping(cpt, original_str, target_str, offset=0):
    # generator which bit flips a ciphertext attempting to go from
    # original string to target string e.g. 'AAAAAAAAAAA' to ';admin=True'
    # i is starting offset within cpt which will be flipped
    # j is the len of the original_str, so flip will happen from cpt[i] until cpt[i+len(original_str)]
    assert(len(original_str) == len(target_str))
    for i in range(offset, len(cpt)-len(original_str)):
        flipped_cpt = list(cpt)
        for j in range(len(original_str)):
            flipped_cpt[i+j] = cpt[i+j] ^ ord(original_str[j]) ^ ord(target_str[j])
        yield bytes(flipped_cpt)

#####################################
# Cipher type/mode detection ahead  #
#####################################

def discover_block_size(oracle):
    initial_len = len(oracle(''))
    for i in range(100):
        new_len = len(oracle('A'*i))
        if new_len - initial_len > 0:
            return new_len - initial_len

def detect_aes_block_cipher_mode(oracle, block_size):
    blocks = break_raw_into_chunks(oracle('A'*block_size*3), block_size)
    return 'ECB' if sum([1 for b1, b2 in list(itertools.combinations(blocks,2)) if b1==b2]) > 0 else 'CBC'

def detect_cipher_type(oracle):
    cpt1 = oracle('A' * 1)
    size = 2
    for _ in range(65):  # run maximum of 65 times
        cpt2 = oracle('A' * size)
        if len(cpt2) - len(cpt1) == 1:
            return 'stream'
        elif len(cpt2) > len(cpt1):
            return 'block'
        cpt1 = cpt2
        size +=1
    return 'hash?'

class RandomCipher(object):
    def __init__(self):
        self.key = Random.new().read(16)
        self.before_bytes = Random.new().read(random.randint(0,20))
        self.after_bytes = Random.new().read(random.randint(0,20))
        self.oracle, self.cipher_type = random.choice([
            (aes_ecb_encrypt, 'block'),
            (aes_cbc_encrypt, 'block'),
            (prng_stream_encrypt, 'stream'),
            (aes_ctr_randomiv_encrypt, 'stream'),
        ])
    def encrypt(self, msg):
        msg = self.before_bytes + ascii_to_raw(msg) + self.after_bytes
        return self.oracle(self.key, msg)

####################################
#       Block Ciphers ahead        #
####################################

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

def aes_cbc_decrypt(key, cpt, iv=''):
    block_size = len(key)
    if not iv:  # if iv is not given, consider it the first block of cpt
        iv, cpt = cpt[:block_size], cpt[block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    msg = cipher.decrypt(cpt)
    return unpad_with_pkcs7(msg)

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

####################################
#      Stream Ciphers ahead        #
####################################

def aes_ctr_encrypt(key, msg, counter):
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(msg)

def aes_ctr_randomiv_encrypt(key, msg):
    counter = Counter.new(8*16, initial_value = int.from_bytes(Random.new().read(16), 'big'))
    iv = counter.next_value().to_bytes(16, byteorder='big')
    # iv = bytes.fromhex(hex(counter.next_value())[2:])  # old, shitty way
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return iv + cipher.decrypt(msg)

def aes_ctr_randomiv_decrypt(key, cpt):
    counter = Counter.new(8*16, initial_value = int.from_bytes(cpt[:16],'big'))
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(cpt[16:])

def prng_stream_encrypt(seed, msg):
    seed = int.from_bytes(seed, byteorder='big')
    gen = prng(seed)
    # 0xFF mask to only get 8 bits from each rng iteration
    keystream = bytes([next(gen)&0xFF for _ in range(len(msg))])
    return xor(keystream, msg)

####################################
#            PRNG  ahead           #
####################################

def prng(seed, initial_element=0):
    """ MT19937 Mersenne Twister RNG. Is a python generator. Usage:
        gen = rng(<seed>)
        random_value = next(gen)    
        next_random_value = next(gen) """
    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    f = 1812433253
    lower_mask = (1 << r) - 1
    upper_mask = 0xFFFFFFFF & ~lower_mask

    index = n
    MT = [0] * n
    MT[0] = seed

    # Initialize the generator from a seed
    for i in range(1,n):
        MT[i] = (f * (MT[i-1] ^ (MT[i-1] >> (w-2))) + i) & 0xFFFFFFFF # 32 bits mask

    j = 0

    while True:
        if index >= n:
            # twist - generate the next n values from the series x_i 
            for i in range(n):
                x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
                xA = x >> 1
                if (x % 2) != 0:
                    xA = xA ^ a
                MT[i] = MT[(i + m) % n] ^ xA
            index = 0
        y = MT[index]
        y = y ^ ((y >> u) & d)
        y = y ^ ((y << s) & b)
        y = y ^ ((y << t) & c)
        y = y ^ (y >> l)
        index += 1
        if j != initial_element:  # this runs initial_element before yielding
            j+=1
        else:
            yield 0xFFFFFFFF & y  # returns the first 32 bits of y

def bruteforce_prng_seed(prng, random_values, start=0, stop=0xFFFF,
                         initial_prng_element=0, bit_mask=0xFFFFFFFF):

    random_values =  random_values if isinstance(random_values, list) else [random_values]  # in case random_values is a single element
    key_attempt = start

    while key_attempt <= stop:
        gen = prng(key_attempt, initial_element=initial_prng_element)
        mismatch = False

        for val in random_values:
            if val != (next(gen) & bit_mask):
                mismatch = True
                key_attempt += 1
                break
        if not mismatch:
            return key_attempt
    return None

####################################
#        Hashing/MAC ahead         #
####################################

def _left_rotate(n, b):
    # Left rotate a 32-bit integer n by b bits
    return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def _right_rotate(n, b):
    # Right rotate a 32-bit integer n by n bits
    return ((n >> b) | (n << (32 - b))) & 0xffffffff

def _right_rotate_64(n, b):
    # Right rotate a 64-bit integer n by n bits
    return ((n >> b) | (n << (64 - b))) & 0xffffffffffffffff

def md_padding(msg_length, endianess='>', block_size=64):
    # Merkle–Damgard padding
    return b''.join([
        b'\x80',
        b'\x00' * ((block_size - 9 - (msg_length % block_size)) % block_size), 
        struct.pack(endianess + '1Q', msg_length << 3)
    ])

def md_padding_sha512(msg_length, endianess='>'):
    mdi = msg_length % 128
    padlen = (119-mdi) if mdi < 112 else (247-mdi)
    return b''.join([
        b'\x80',
        b'\x00' * padlen,
        struct.pack(endianess + '1Q', msg_length << 3)
    ])

def sha1(msg, state=(0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0), fake_len=0, raw=False):
    # source https://github.com/ajalt/python-sha1/blob/master/sha1.py

    def _process_chunk(chunk, h0, h1, h2, h3, h4):
        # Process a chunk of data and return the new digest variables.
        assert len(chunk) == 64

        w = [0] * 80

        w[:16] = struct.unpack('>16L', chunk)

        # Extend the sixteen 4-byte words into eighty 4-byte words
        for i in range(16, 80):
            w[i] = _left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
        
        # Initialize hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4
        
        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
        
            a, b, c, d, e = ((_left_rotate(a, 5) + f + e + k + w[i]) & 0xffffffff, 
                            a, _left_rotate(b, 30), c, d)
        
        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

        return h0, h1, h2, h3, h4

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg))

    for chunk in break_raw_into_chunks(msg, 64):
        state = _process_chunk(chunk, *state)
    
    output = struct.pack('>5I', *state)
    return output if raw else raw_to_hex(output)

def sha256(msg, state=(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19), fake_len=0, raw=False):

    k = (
       0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
   )

    def _process_chunk(chunk, h0, h1, h2, h3, h4, h5, h6, h7):
        w = [0]*64

        w[:16] = struct.unpack('>16L', chunk)

        for i in range(16, 64):
            s0 = _right_rotate(w[i-15], 7) ^ _right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _right_rotate(w[i-2], 17) ^ _right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffff
        
        a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7

        for i in range(64):
            s0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
            s1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[i] + w[i]
            
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        
        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
        h5 = (h5 + f) & 0xffffffff
        h6 = (h6 + g) & 0xffffffff
        h7 = (h7 + h) & 0xffffffff
        return h0, h1, h2, h3, h4, h5, h6, h7

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg))

    for chunk in break_raw_into_chunks(msg, 64):
        state = _process_chunk(chunk, *state)

    output = struct.pack('>8I', *state)
    return output if raw else raw_to_hex(output)

def sha224(msg, state=(0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4), fake_len=0, raw=False):
    # Reuses sha256 implementation
    state_from_sha256 = struct.unpack('>8I', sha256(msg, state, fake_len, raw=True))
    output = struct.pack('>7I', *state_from_sha256[:-1])
    return output if raw else raw_to_hex(output)

def sha512(msg, state=(0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179), fake_len=0, raw=False):
    k = (

        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    )

    def _process_chunk(chunk, h0, h1, h2, h3, h4, h5, h6, h7):
        w = [0]*80
        w[:16] = struct.unpack('>16Q', chunk)

        for i in range(16, 80):
            s0 = _right_rotate_64(w[i-15], 1) ^ _right_rotate_64(w[i-15], 8) ^ (w[i-15] >> 7)
            s1 = _right_rotate_64(w[i-2], 19) ^ _right_rotate_64(w[i-2], 61) ^ (w[i-2] >> 6)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xffffffffffffffff
        
        a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7

        for i in range(80):
            s0 = _right_rotate_64(a, 28) ^ _right_rotate_64(a, 34) ^ _right_rotate_64(a, 39)
            s1 = _right_rotate_64(e, 14) ^ _right_rotate_64(e, 18) ^ _right_rotate_64(e, 41)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            ch = (e & f) ^ ((~e) & g)
            t1 = h + s1 + ch + k[i] + w[i]
            
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffffffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffffffffffff
        
        h0 = (h0 + a) & 0xffffffffffffffff
        h1 = (h1 + b) & 0xffffffffffffffff
        h2 = (h2 + c) & 0xffffffffffffffff
        h3 = (h3 + d) & 0xffffffffffffffff
        h4 = (h4 + e) & 0xffffffffffffffff
        h5 = (h5 + f) & 0xffffffffffffffff
        h6 = (h6 + g) & 0xffffffffffffffff
        h7 = (h7 + h) & 0xffffffffffffffff
        return h0, h1, h2, h3, h4, h5, h6, h7

    msg = ascii_to_raw(msg)
    msg += md_padding_sha512(fake_len or len(msg))

    for chunk in break_raw_into_chunks(msg, 128):
        state = _process_chunk(chunk, *state)

    output = struct.pack('>8Q', *state)
    return output if raw else raw_to_hex(output)

def md4(msg, state=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), fake_len=0, raw=False):
    # source http://www.acooke.org/cute/PurePython0.html
    def f(x, y, z): return x & y | ~x & z
    def g(x, y, z): return x & y | x & z | y & z
    def h(x, y, z): return x ^ y ^ z
    def f1(a, b, c, d, k, s, X): return _left_rotate(a + f(b, c, d) + X[k], s)
    def f2(a, b, c, d, k, s, X): return _left_rotate(a + g(b, c, d) + X[k] + 0x5a827999, s)
    def f3(a, b, c, d, k, s, X): return _left_rotate(a + h(b, c, d) + X[k] + 0x6ed9eba1, s)
    
    def _process_chunk(x, h0, h1, h2, h3):
        a, b, c, d = h0, h1, h2, h3
        
        x = struct.unpack('<16L', x)

        a = f1(a,b,c,d, 0, 3, x)
        d = f1(d,a,b,c, 1, 7, x)
        c = f1(c,d,a,b, 2,11, x)
        b = f1(b,c,d,a, 3,19, x)
        a = f1(a,b,c,d, 4, 3, x)
        d = f1(d,a,b,c, 5, 7, x)
        c = f1(c,d,a,b, 6,11, x)
        b = f1(b,c,d,a, 7,19, x)
        a = f1(a,b,c,d, 8, 3, x)
        d = f1(d,a,b,c, 9, 7, x)
        c = f1(c,d,a,b,10,11, x)
        b = f1(b,c,d,a,11,19, x)
        a = f1(a,b,c,d,12, 3, x)
        d = f1(d,a,b,c,13, 7, x)
        c = f1(c,d,a,b,14,11, x)
        b = f1(b,c,d,a,15,19, x)

        a = f2(a,b,c,d, 0, 3, x)
        d = f2(d,a,b,c, 4, 5, x)
        c = f2(c,d,a,b, 8, 9, x)
        b = f2(b,c,d,a,12,13, x)
        a = f2(a,b,c,d, 1, 3, x)
        d = f2(d,a,b,c, 5, 5, x)
        c = f2(c,d,a,b, 9, 9, x)
        b = f2(b,c,d,a,13,13, x)
        a = f2(a,b,c,d, 2, 3, x)
        d = f2(d,a,b,c, 6, 5, x)
        c = f2(c,d,a,b,10, 9, x)
        b = f2(b,c,d,a,14,13, x)
        a = f2(a,b,c,d, 3, 3, x)
        d = f2(d,a,b,c, 7, 5, x)
        c = f2(c,d,a,b,11, 9, x)
        b = f2(b,c,d,a,15,13, x)

        a = f3(a,b,c,d, 0, 3, x)
        d = f3(d,a,b,c, 8, 9, x)
        c = f3(c,d,a,b, 4,11, x)
        b = f3(b,c,d,a,12,15, x)
        a = f3(a,b,c,d, 2, 3, x)
        d = f3(d,a,b,c,10, 9, x)
        c = f3(c,d,a,b, 6,11, x)
        b = f3(b,c,d,a,14,15, x)
        a = f3(a,b,c,d, 1, 3, x)
        d = f3(d,a,b,c, 9, 9, x)
        c = f3(c,d,a,b, 5,11, x)
        b = f3(b,c,d,a,13,15, x)
        a = f3(a,b,c,d, 3, 3, x)
        d = f3(d,a,b,c,11, 9, x)
        c = f3(c,d,a,b, 7,11, x)
        b = f3(b,c,d,a,15,15, x)

        return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff]

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg), '<')

    for chunk in break_raw_into_chunks(msg, 64):
        state = _process_chunk(chunk, *state)

    output = struct.pack('<4I', *state)
    return output if raw else raw_to_hex(output)

def md5(msg, state=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), fake_len=0, raw=False):
    s = (
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
    )

    K = (
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    )

    def _process_chunk(x, h0, h1, h2, h3):
        a, b, c, d = h0, h1, h2, h3
        
        X = struct.unpack('<16L', x)

        for i in range(64):
            if 0 <= i <= 15:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i <= 31:
                f = (d & b) | (~d & c)
                g = (5*i + 1) % 16
            elif 32 <= i <= 47:
                f = b ^ c ^ d
                g = (3*i + 5) % 16
            elif 48 <= i <= 63:
                f = c ^ (b | ~d)
                g = (7*i) % 16
            
            dtemp = d
            d = c
            c = b
            b = b + _left_rotate((a + f + K[i] + X[g]), s[i])
            a = dtemp

        return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff]

    msg = ascii_to_raw(msg)
    msg += md_padding(fake_len or len(msg), '<')

    for chunk in break_raw_into_chunks(msg, 64):
        state = _process_chunk(chunk, *state)

    output = struct.pack('<4I', *state)
    return output if raw else raw_to_hex(output)

def length_extension(hash_function, original_tag, original_msg, append_msg, max_key_len=64):
    if not isinstance(original_tag, bytes):
        original_tag = hex_to_raw(original_tag)

    endianess = '<' if hash_function in [md4, md5] else '>'

    if hash_function in [sha512]:
        struct_settings = '>8Q'
        padding = md_padding_sha512
    else:
        struct_settings = endianess + str(len(original_tag)//4) + 'L'
        padding = md_padding

    h = struct.unpack(struct_settings, original_tag)

    msg_tag_pairs = []

    for key_length in range(max_key_len):
        msg = original_msg + padding(len(b'a'*key_length + original_msg), endianess) + append_msg
        tag = hash_function(append_msg, h, len(msg) + key_length)
        msg_tag_pairs.append((msg, tag))

    return msg_tag_pairs

def hmac(key, msg, hash_function=sha1, raw=False):
    if (len(key) > 64):
        key = hash_function(key, raw=True)
    if (len(key) < 64):
        key = key + b'\x00' * (64 - len(key))
   
    o_key_pad = xor(b'\x5c' * 64, key)
    i_key_pad = xor(b'\x36' * 64, key)

    output = hash_function(o_key_pad + hash_function(i_key_pad + msg, raw=True), raw=True)
    return output if raw else raw_to_hex(output)

def hmac_timing_leak_bruteforce(msg, hash_function=sha1, url='http://localhost:5000?msg={}&tag={}'):

    hashlen = len(hash_function(b'test',raw=True))
    payload = [0] * hashlen

    for i in range(len(payload)):

        counter = {}
        
        while True:
            slowest_delay = 0
            slowest_val = 0

            for j in range(256):
                payload[i] = j
                this_tag_attempt = raw_to_hex(payload)

                start_time = time.perf_counter()
                try:
                    urllib.request.urlopen(url.format(msg, this_tag_attempt))
                except urllib.error.HTTPError as e:
                    pass
                runtime = time.perf_counter() - start_time

                if runtime > slowest_delay:
                    slowest_delay = runtime
                    slowest_val = j
            
            counter[slowest_val] = counter.setdefault(slowest_val, 0) + 1
            if counter[slowest_val] == 3:
                payload[i] = slowest_val
                print('Found next byte - {}'.format(raw_to_hex(payload[:i+1])))
                break

    tag = raw_to_hex(payload)
    assert(urllib.request.urlopen(url.format(msg, tag)).getcode() == 200)
    return tag

def supported_hashes():
    return [md4, md5, sha1, sha256, sha224, sha512]

def guess_hash_type(thishash):
    # Guesses likely hashing algorithm based on hash length
    if not isinstance(thishash, bytes):
        thishash = hex_to_raw(thishash)

    if len(thishash) == 16:
        return [md4, md5]
    elif len(thishash) == 20:
        return [sha1]
    elif len(thishash) == 28:
        return [sha224]
    elif len(thishash) == 32:
        return [sha256]
    elif len(thishash) == 64:
        return [sha512]

####################################
#               Math               #
####################################

def modexp(base, exponent, modulus):   
    if modulus == 1:
        return 0
    result = 1
    base = base % modulus
    while exponent > 0:
        if (exponent % 2 == 1):
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def egcd(b, n):
    # wtf?
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def find_cube_root(n):
    lo = 0
    hi = n
    while lo < hi:
        mid = (lo+hi)//2
        if mid**3 < n:
            lo = mid+1
        else:
            hi = mid
    return lo

####################################
#        Public key crypto         #
####################################

class DH():
    # Diffie Hellman
    # Refer to https://datatracker.ietf.org/doc/rfc3526/?include_text=1 for constants
    default_p = 2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919  # raw_to_int(hex_to_raw('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff'))
    default_g = 2

    def __init__(self, p=default_p, g=default_g, peer_public_key=None):
        self.p = p
        self.g = g
        self.private_key = raw_to_int(urandom(128)) % p
        self.public_key = modexp(g, self.private_key, p)
        if peer_public_key:
            self.key_exchange(peer_public_key)

    def key_exchange(self, peer_public_key):
        self.shared_secret = int_to_raw(modexp(peer_public_key, self.private_key, self.p))
        self.shared_key = sha1(self.shared_secret, raw=True)[:16]

class SRPServer():
    # Secure Remote Password (SRP) Server implementation

    def __init__(self, g=2, k=3, N=2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919 ):
        self.N = N
        self.g = g
        self.k = k
        self.users = {}
        self.create_user('luis@teix.co', 'password')
        self.create_user('test@gmail.com', 'secret')

    def create_user(self, email, password):
        password = ascii_to_raw(password)
        salt = urandom(4)
        x = raw_to_int(sha256(salt + password, raw=True))
        v = modexp(self.g, x, self.N)
        self.users[email] = {'salt': salt, 'v': v}

    def key_exchange(self, email, client_public_key):
        v, salt = self.users[email]['v'], self.users[email]['salt']
        this_private_key = raw_to_int(urandom(16)) % self.N
        this_public_key = self.k * v + modexp(self.g, this_private_key, self.N)
        u = raw_to_int(sha256(int_to_raw(client_public_key + this_public_key), raw=True))
        shared_secret = modexp((client_public_key * modexp(v, u, self.N)), this_private_key, self.N)
        shared_key = sha256(int_to_raw(shared_secret), raw=True)
        self.users[email]['token'] = hmac(shared_key, salt, sha256)
        return salt, this_public_key

    def authenticate(self, email, token):
        return self.users[email]['token'] == token

class SRPClient():
    # Secure Remote Password (SRP) Client implementation

    def __init__(self, email, password, g=2, k=3, N=2410312426921032588552076022197566074856950548502459942654116941958108831682612228890093858261341614673227141477904012196503648957050582631942730706805009223062734745341073406696246014589361659774041027169249453200378729434170325843778659198143763193776859869524088940195577346119843545301547043747207749969763750084308926339295559968882457872412993810129130294592999947926365264059284647209730384947211681434464714438488520940127459844288859336526896320919633919 ):
        self.N = N
        self.g = g
        self.k = k
        self.email = email
        self.password = ascii_to_raw(password)
        self.private_key = raw_to_int(urandom(16)) % self.N
        self.public_key = modexp(self.g, self.private_key, self.N)

    def key_exchange(self, salt, server_public_key):
        u = raw_to_int(sha256(int_to_raw(self.public_key + server_public_key), raw=True))
        x = raw_to_int(sha256(salt + self.password, raw=True))
        shared_secret = modexp((server_public_key - self.k * modexp(self.g,x,self.N)), (self.private_key + u * x), self.N)
        shared_key = sha256(int_to_raw(shared_secret), raw=True)
        self.token = hmac(shared_key, salt, sha256)

class SimplifiedSRPServer(SRPServer):
    def key_exchange(self, email, client_public_key):
        v, salt, u = self.users[email]['v'], self.users[email]['salt'], raw_to_int(urandom(16))
        this_private_key = raw_to_int(urandom(16)) % self.N
        this_public_key = modexp(self.g, this_private_key, self.N)
        shared_secret = modexp(client_public_key * modexp(v, u, self.N), this_private_key, self.N)
        shared_key = sha256(int_to_raw(shared_secret), raw=True)
        self.users[email]['token'] = hmac(shared_key, salt, sha256)
        return salt, this_public_key, u

class SimplifiedSRPClient(SRPClient):
    def key_exchange(self, salt, server_public_key, u):
        x = raw_to_int(sha256(salt + self.password, raw=True))
        shared_secret = modexp(server_public_key, self.private_key + (u * x), self.N)
        shared_key = sha256(int_to_raw(shared_secret), raw=True)
        self.token = hmac(shared_key, salt, sha256)

class RSA():
    def __init__(self):
        e = 3
        while True:
            p = primegen(1024)
            q = primegen(1024)
            n = p*q
            try:
                d = modinv(e, (p-1)*(q-1))
                break
            except Exception:
                pass
        self.public_key = e
        self.private_key = d
        self.n = n

def rsaencrypt(msg, e, n):
    if not isinstance(msg, int):
        msg = raw_to_int(ascii_to_raw(msg))
    return modexp(msg, e, n)

def rsadecrypt(cpt, d, n):
    return int_to_raw(modexp(cpt, d, n))
