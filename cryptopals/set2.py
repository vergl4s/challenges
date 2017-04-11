#!/usr/bin/env python3
import random
from utils import *

def challenge9():
    # Implement PKCS#7 padding
    assert(b'THIS IS' == aes_cbc_decrypt('YELLOW SUBMARINE', aes_cbc_encrypt('YELLOW SUBMARINE', 'THIS IS')))
    assert(b'THIS IS IT MOTHAFUCKA' == aes_cbc_decrypt('YELLOW SUBMARINE', aes_cbc_encrypt('YELLOW SUBMARINE', 'THIS IS IT MOTHAFUCKA')))
    assert(b'1234567890123456' == aes_cbc_decrypt('YELLOW SUBMARINE', aes_cbc_encrypt('YELLOW SUBMARINE', '1234567890123456')))
    return True

def challenge10():
    # Implement CBC mode
    cpt = b64_to_raw('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')
    key = 'YELLOW SUBMARINE'
    iv = hex_to_raw('00'*16)
    msg = b''
    cpt_blocks = break_raw_into_chunks(cpt,16)
    cipher = AES.new(key, AES.MODE_ECB)
    
    for this_cpt in cpt_blocks:
        this_msg = xor(cipher.decrypt(this_cpt), iv)
        iv = this_cpt
        msg += this_msg

    return msg[:-msg[-1]]

def challenge11():
    # An ECB/CBC detection oracle

    def oracle(msg):
        key = Random.new().read(16)
        before_bytes = Random.new().read(random.randint(5,10))
        after_bytes = Random.new().read(random.randint(5,10))
        msg = before_bytes + ascii_to_raw(msg) + after_bytes

        if random.randint(0,1) == 0:  # ECB
            return aes_ecb_encrypt(key, msg), 'ECB'
        else:  # CBC
            return aes_cbc_encrypt(key, msg), 'CBC'

    # msg = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.'
    msg = 'A' * 16 * 3
    right_answers = 0
    for _ in range(10):
        cpt, cipher_type = oracle(msg)
        blocks = break_raw_into_chunks(cpt,16)
        score = sum([1 for b1, b2 in list(itertools.combinations(blocks,2)) if b1==b2])
        guess = 'ECB' if score > 0 else 'CBC'
        if guess == cipher_type:
            right_answers += 1
        else:
            print("Guessed wrong :( {} != {}".format(cipher_type, guess))

    return right_answers

def challenge12():
    # Byte-at-a-time ECB decryption (Simple)

    key = Random.new().read(16)  # calculated only once when challenge12 is called
    
    def oracle(msg):
        extra = raw_to_ascii(b64_to_raw('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'))
        return aes_ecb_encrypt(key, msg+extra)

    block_size = discover_block_size(oracle)
    mode = detect_aes_block_cipher_mode(oracle, block_size)
    return aes_ecb_find_secret_appended_text(oracle, block_size)

def challenge13():
    # ECB cut-and-paste

    key = Random.new().read(16)

    def sanitize_email(email):
        return email.replace('&','').replace('=','')

    def profile_for(email):
        # To simulate user creation, any email can be used to create a profile
        email = sanitize_email(email)
        if email == 'admin@teix.co':
            d = { 'uid': 1, 'role': 'admin', 'email': email}
        else:
            d = { 'uid': 10, 'role': 'user', 'email': email}

        return aes_ecb_encrypt(key, encode_dict_as_post_request(d))

    def check_result(ciphertext):
        d = parse_post_request(raw_to_ascii(aes_ecb_decrypt(key, ciphertext)))
        return "Hello {}, you are {}".format(d['email'],d['role'])

    def parse_post_request(post):
        d = {}
        for kv in [kv for kv in post.split('&')]:
            k, v = kv.split('=')
            d[k] = v
        return d

    def encode_dict_as_post_request(d):
        return 'email={}&uid={}&role={}'.format(d['email'],d['uid'],d['email'])

    # Real response
    # 'email=foo@AAAbar' '.co&uid=10&role=' 'user'+0xc*12
    # Creating artificial role block with 'foo@BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAadmin'+'\x0b'*11+'.co'
    # 'email=foo@AAAAAA' 'BBBBBBBBBBBBAAAA' 'BBBBBBBBBBBBAAAA' 'admin'+0xb*11 '.co&uid=10&role=' 'user'+0xc*12
    # Just have to replace the last block on the real ciphertext with the forth block in the artificial response

    cpt = break_raw_into_chunks(profile_for('foo@AAAbar.co'),16)
    fake_cpt = break_raw_into_chunks(profile_for('foo@BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAAadmin'+'\x0b'*11+'.co'),16)
    cpt[-1] = fake_cpt[3]

    return check_result(b''.join(cpt))

def challenge14():
    # Byte-at-a-time ECB decryption (Harder)

    key = Random.new().read(16)
    prepend = Random.new().read(random.randint(10,64))
    append = b64_to_raw('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

    def oracle(msg):
        return aes_ecb_encrypt(key, prepend+ascii_to_raw(msg)+append)

    block_size = discover_block_size(oracle)
    return aes_ecb_find_secret_appended_text(oracle, block_size)

def challenge15():
    # PKCS#7 padding validation

    assert(unpad_with_pkcs7("ICE ICE BABY\x04\x04\x04\x04") == b"ICE ICE BABY")  # good
    try:
        unpad_with_pkcs7("ICE ICE BABY\x05\x05\x05\x05")  # bad
        return False
    except ValueError:
        pass
    try:
        unpad_with_pkcs7("ICE ICE BABY\x01\x02\x03\x04")  # bad
        return False
    except ValueError:
        pass 
    return True

def challenge16():
    # CBC bitflipping atatcks

    key = Random.new().read(16)
    prepend = b'comment1=cooking%20MCs;userdata='
    append = b';comment2=%20like%20a%20pound%20of%20bacon'

    def oracle(msg):
        msg = msg.replace(';', '%3B').replace('=', '%3D')
        return aes_cbc_encrypt(key, prepend+ascii_to_raw(msg)+append)

    def check_if_admin(cpt):
        msg = raw_to_ascii(aes_cbc_decrypt(key, cpt))
        for pair in [pair.split('=') for pair in msg.split(';')]:
            if len(pair) > 1:
                if  pair[0] in 'admin' and pair[1] in 'true':
                    return True
        return False


    # cpt = break_raw_into_chunks(oracle('thisisevilblock!' + 'AAAAA|admin|true'), 16)
    
    # # Need to change cpt[3] to impact the clear text of cpt[4]
    # new_fourth_block = list(cpt[3])
    # new_fourth_block[5] = new_fourth_block[5] ^ ord('|') ^ ord(';')
    # new_fourth_block[11] = new_fourth_block[11] ^ ord('|') ^ ord('=')
    # cpt[3] = bytearray(new_fourth_block)
    # return check_if_admin(b''.join(cpt))

    for i in range(len(key)):  # 'BBBBBBBBBBBB' needs to be within a single block, so 'A' padding will be varied until we get it right
        cpt = oracle('A'*i + 'BBBBBBBBBBBB')
        gen =  targeted_bit_flipping(cpt, 'BBBBBBBBBBBB', ';admin=true;')
        while True:
            try:
                flipped = next(gen)
                if check_if_admin(flipped):
                    return True
            except ValueError as e:
                pass

if __name__ == '__main__':
    print(challenge16())
