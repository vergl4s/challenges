#!/usr/bin/env python3

from utils import *

def challenge25():
    # Break "random access read/write" AES CTR

    key = b'`DDWxh\xb2\x05\xec\xd5\x08\xef/[\xac\xfa'  # Random.new().read(16)
    iv_initial_value = 110348971695297938955950658941185344903  # int.from_bytes(Random.new().read(16), 'big')
    file = aes_ecb_decrypt(b'YELLOW SUBMARINE', b64_to_raw('CRIwqt4+szDbqkNY+I0qbDe3LQz0wiw0SuxBQtAM5TDdMbjCMD/venUDW9BL`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'))
    cpt = aes_ctr_encrypt(key, file, Counter.new(8*16, initial_value = iv_initial_value))
    
    def edit(cpt, offset, newtext):
        # edits cpt using previously stored key and iv
        keystream = aes_ctr_encrypt(key, '\x00'*len(cpt), Counter.new(8*16, initial_value = iv_initial_value))  # seeking forward
        cpt = list(cpt)
        return newtext ^ keystream[offset]

    new_cpt = [edit(cpt, i, cpt[i]) for i in range(len(cpt))]
    new_cpt = bytes(new_cpt)
    return True if new_cpt == file else False

def challenge26():
    # CTR bitflipping

    key = Random.new().read(16)
    prepend = b'comment1=cooking%20MCs;userdata='
    append = b';comment2=%20like%20a%20pound%20of%20bacon'

    def oracle(msg):
        msg = msg.replace(';', '%3B').replace('=', '%3D')
        return aes_ctr_randomiv_encrypt(key, prepend+ascii_to_raw(msg)+append)

    def check_if_admin(cpt):
        msg = raw_to_ascii(aes_ctr_randomiv_decrypt(key, cpt))
        for pair in [pair.split('=') for pair in msg.split(';')]:
            if len(pair) > 1:
                if  pair[0] in 'admin' and pair[1] in 'true':
                    return True
        return False

    cpt = oracle('AAAAAAAAAAAA')
    gen =  targeted_bit_flipping(cpt, 'AAAAAAAAAAAA', ';admin=true;')
    while True:
        flipped = next(gen)
        if check_if_admin(flipped):
            return True

def challenge27():
    # Recover the key from CBC with IV=Key

    key = Random.new().read(16)

    def sender():
        msg = b64_to_raw('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
        return aes_cbc_encrypt(key, msg, iv=key)[16:]  # ignores IV - no need to preppend it if it is the key
    
    def receiver(cpt):
        msg = aes_cbc_decrypt(key, cpt, iv=key)
        if [c for c in msg if c > 127]:
            raise ValueError("Something weird in message - {}".format(msg))
        return msg

    in_transit_cpt = list(sender())
    in_transit_cpt[16:16*2] = b'\x00'*16
    in_transit_cpt[16*2:16*3] = in_transit_cpt[:16]
    in_transit_cpt = bytes(in_transit_cpt)

    try:
        receiver(in_transit_cpt)
    except ValueError as e:
        broken_plaintext = parse_unicode_str(str(e).split('Something weird in message - b')[1][1:-1])
        broken_plaintext = break_raw_into_chunks(broken_plaintext, 16)
        if xor(broken_plaintext[0], broken_plaintext[2]) == key:
            return True

def challenge28():
    # Implement a SHA-1 keyed MAC

    key = Random.new().read(16)
    
    def sign(msg):
        return sha1(key + msg)

    def verify_tag(msg, tag):
        if tag == sha1(key + msg):
            return True
        return False

    msg = b"user=test;admin=false"
    tag = sign(msg)
    msg = b"user=test;admin=True"
    return not verify_tag(msg, tag)

def challenge29():
    # Break a SHA-1 keyed MAC using length extension
    
    key = Random.new().read(random.randint(4,32))
    original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    original_tag = sha1(key + original_msg)

    def verify_tag(msg, tag):
        if tag == sha1(key + msg):
            return True
        return False

    msg_tag_pairs = length_extension(sha1, original_tag, original_msg, b';admin=true', 'big')

    for msg, tag in msg_tag_pairs:
        if verify_tag(msg, tag):
            # print('Key length = {}\nMsg = {}\nTag = {}'.format(msg_tag_pairs.index((msg, tag)), msg, tag))
            return True

def challenge30():
    # Break an MD4 keyed MAC using length extension

    key = Random.new().read(random.randint(4,32))
    original_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    original_tag = md4(key + original_msg)

    def verify_tag(msg, tag):
        if tag == md4(key + msg):
            return True
        return False

    msg_tag_pairs = length_extension(md4, original_tag, original_msg, b';admin=true', 'little')

    for msg, tag in msg_tag_pairs:
        if verify_tag(msg, tag):
            # print('Key length = {}\nMsg = {}\nTag = {}'.format(msg_tag_pairs.index((msg, tag)), msg, tag))
            return True

def challenge31_and_32(msg='thisisasecretmessage'):
    # Implement and break HMAC-SHA1 with an artificial timing leak
    
    import threading
    threading.Thread(target=challenge31_and_32_server, name="webserver", daemon=True).start()
    time.sleep(0.5)  # waiting for webserver to start

    print('Starting hmac timing leak brute force')
    tag = hmac_timing_leak_bruteforce(msg)

    return "Tag for {} is {}".format(msg, tag)

def challenge31_and_32_server(artificial_delay=0.002, key=Random.new().read(random.randint(16,64))):
    
    from flask import Flask, request, abort
    app = Flask(__name__)

    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

    @app.route("/")
    def main():
        msg = ascii_to_raw(request.args.get('msg'))
        user_supplied_tag = hex_to_raw(request.args.get('tag'))
        right_tag = hmac(key, msg, raw=True)
        for i in range(len(right_tag)):
            if right_tag[i] == user_supplied_tag[i]:
                time.sleep(artificial_delay)  
            else:
                abort(500)
        return 'ok'

    @app.route("/answer")
    def answer():
        msg = ascii_to_raw(request.args.get('msg'))
        right_tag = hmac(key, msg, raw=True)
        return raw_to_hex(right_tag) 

    app.run(threaded=True)

if __name__ == '__main__':
    print(challenge31_and_32())