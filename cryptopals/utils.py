import binascii
import itertools
import hashlib
from math import ceil
import random
import string
import struct
import time
import urllib.request

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA
from Crypto.Util import Counter

def raw_to_b64(raw):
    return binascii.b2a_base64(raw).rstrip()

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
    # return struct.pack(">I", big_int)  # left for reference
    return big_int.to_bytes(16, byteorder='big')

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

def cpt_bit_flipping(cpt, original_str, target_str, offset=0):
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

def test_cipher_detection():
    for _ in range(1000):
        cipher = RandomCipher()
        assert(detect_cipher_type(cipher.encrypt) == cipher.cipher_type)
    return True

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
    """Left rotate a 32-bit integer n by b bits."""
    # return ((n << b) | (n >> (32 - b))) & 0xffffffff
    return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def md_padding(msg_length, endianess='big'):
    # Merkle–Damgård padding
    return b''.join([
        # append the bit '1' to the message
        b'\x80',
        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        b'\x00' * ((56 - (msg_length + 1) % 64) % 64), 
        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        (msg_length * 8).to_bytes(8, byteorder=endianess)
    ])

def sha1(msg, state=(0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0), fake_len=0, output_as_raw=False):
    # source https://github.com/ajalt/python-sha1/blob/master/sha1.py

    def _process_chunk(chunk, h0, h1, h2, h3, h4):
        """Process a chunk of data and return the new digest variables."""
        assert len(chunk) == 64

        w = [0] * 80

        # Break chunk into sixteen 4-byte big-endian words w[i]
        for i in range(16):
            w[i] = int.from_bytes(chunk[i*4:i*4 + 4], byteorder='big')

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

    msg += md_padding(fake_len or len(msg))

    for chunk in break_raw_into_chunks(msg, 64):
        state = _process_chunk(chunk, *state)

    output = b''.join(h.to_bytes(4, byteorder='big') for h in state)
    return output if output_as_raw else raw_to_hex(output)


def md4(msg, state=(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476), fake_len=0, output_as_raw=False):
    # source http://www.acooke.org/cute/PurePython0.html
    def f(x, y, z): return x & y | ~x & z
    def g(x, y, z): return x & y | x & z | y & z
    def h(x, y, z): return x ^ y ^ z
    def f1(a, b, c, d, k, s, X): return _left_rotate(a + f(b, c, d) + X[k], s)
    def f2(a, b, c, d, k, s, X): return _left_rotate(a + g(b, c, d) + X[k] + 0x5a827999, s)
    def f3(a, b, c, d, k, s, X): return _left_rotate(a + h(b, c, d) + X[k] + 0x6ed9eba1, s)
    
    def _process_chunk(x, h0, h1, h2, h3):
        a, b, c, d = h0, h1, h2, h3
        x = [int.from_bytes(i, byteorder='little') for i in break_raw_into_chunks(x,4)]

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

    msg += md_padding(fake_len or len(msg), 'little')

    for chunk in break_raw_into_chunks(msg, 64):
        state = _process_chunk(chunk, *state)
    
    output = b''.join(h.to_bytes(4, byteorder='little') for h in state)
    return output if output_as_raw else raw_to_hex(output)

def length_extension(hash_function, original_tag, original_msg, append_msg, endianness=('big','little'), max_key_len=64):
    if isinstance(endianness, str):
        endianness = [endianness]

    msg_tag_pairs = []
    
    for e in endianness:
        h = [int.from_bytes(i, byteorder=e) for i in break_raw_into_chunks(hex_to_raw(original_tag), 4)]
        
        for key_length in range(max_key_len):
            msg = original_msg + md_padding(len(b'a'*key_length + original_msg), e) + append_msg
            tag = hash_function(append_msg, h, len(msg) + key_length)
            msg_tag_pairs.append((msg, tag))

    return msg_tag_pairs

def hmac(key, msg, hash_function=sha1, output_as_raw=False):
    if (len(key) > 64):
        key = hash_function(key, output_as_raw=True)
    if (len(key) < 64):
        key = key + b'\x00' * (64 - len(key))
   
    o_key_pad = xor(b'\x5c' * 64, key)
    i_key_pad = xor(b'\x36' * 64, key)

    output = hash_function(o_key_pad + hash_function(i_key_pad + msg, output_as_raw=True), output_as_raw=True)
    return output if output_as_raw else raw_to_hex(output)

def hmac_timing_leak_bruteforce(msg, hash_function=sha1, url='http://localhost:5000?msg={}&tag={}'):

    hashlen = len(hash_function(b'test',output_as_raw=True))
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