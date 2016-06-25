#!/usr/bin/env python3

from utils import *

from Crypto.Hash import HMAC, SHA

def challenge33():
    # Implement Diffie-Hellman

    alice = DH()
    bob = DH(alice.p, alice.g, alice.public_key)
    alice.key_exchange(bob.public_key)
    return alice.shared_key == bob.shared_key

def challenge34():
    # Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

    msg1 = b'Hey Bob, how have you been?'
    msg2 = b'All good, Alice, how you doing?'

    # Regular exchange
    alice = DH()
    # Alice -> Bob - p, g, A
    bob = DH(alice.p, alice.g, alice.public_key)
    # Bob -> Alice - B
    alice.key_exchange(bob.public_key)
    assert(alice.shared_key == bob.shared_key)
    # Alice -> Bob - cpt1
    cpt_from_alice = aes_cbc_encrypt(alice.shared_key, msg1)
    # Bob decrypts cpt1
    assert(aes_cbc_decrypt(bob.shared_key, cpt_from_alice) == msg1)
    # Bob -> Alice - cpt2
    cpt_from_bob = aes_cbc_encrypt(bob.shared_key, msg2)
    # Alice decrypts cpt2
    assert(aes_cbc_decrypt(alice.shared_key, cpt_from_bob) == msg2)
    
    # Mitm exchange
    # Attacker provides p as public key to both Alice and Bob. If p is public key, key_exchange will do:
    # p ** private_key % p which will always be 0 (p*p*p*p...*p % p == 0)
    
    alice = DH()
    # Eve -> Bob - p, g, p
    bob = DH(alice.p, alice.g, alice.p)
    # Eve -> Alice - p
    alice.key_exchange(alice.p)
    assert(alice.shared_secret == bob.shared_secret == b'\x00')
    
    # Eve now knows the shared secret is 0, hence the sha1 generated key is predictable
    eve_compromised_key = sha1(b'\x00', raw=True)[:16]

    # Alice -> Bob - cpt1
    cpt_from_alice = aes_cbc_encrypt(alice.shared_key, msg1)
    # Eve can decrypt cpt1
    assert(aes_cbc_decrypt(eve_compromised_key, cpt_from_alice) == msg1)
    # Bob -> Alice - cpt2
    cpt_from_bob = aes_cbc_encrypt(bob.shared_key, msg2)
    # Eve can decrypt cpt2
    assert(aes_cbc_decrypt(eve_compromised_key, cpt_from_bob) == msg2)

    return True


def challenge35():
    # Implement DH with negotiated groups, and break with malicious "g" parameters

    # g = 1     => shared_secret will be 1 for any private_key (1 ** private_key % p == 1)
    # g = p     => shared_secret will be 0 for any private_key (p ** private_key % p == 0)
    # g = p -1  => shared_secret will be:
    #               1 when private_key is even ((p-1)**private_key % p == 1 if private_key is even) 
    #               p-1 when private_key is odd ((p-1)**private_key % p == (p-1) if private_key is odd) 
    
    # g = 1
    alice = DH(g=1)  # suppose Eve is starting a connection to both Alice and Bob with chosen group
    bob = DH(alice.p, alice.g)
    bob.key_exchange(alice.public_key)
    alice.key_exchange(bob.public_key)
    assert(alice.shared_secret == bob.shared_secret == b'\x01')
    eve_compromised_key = sha1(b'\x01', raw=True)[:16]
    assert(alice.shared_key == bob.shared_key == eve_compromised_key)


    # g = p
    captured_p = DH().p
    alice = DH(captured_p, captured_p)  # suppose Eve captures Alice's initial group, and then starts a ney kew_exchange
    bob = DH(alice.p, alice.p)
    bob.key_exchange(alice.public_key)
    alice.key_exchange(bob.public_key)
    assert(alice.shared_secret == bob.shared_secret == b'\x00')
    eve_compromised_key = sha1(b'\x00', raw=True)[:16]
    assert(alice.shared_key == bob.shared_key == eve_compromised_key)

    # g = p - 1
    captured_p = DH().p
    alice = DH(captured_p, captured_p-1)  # suppose Eve captures Alice's initial group, and then starts a ney kew_exchange
    bob = DH(alice.p, alice.g)
    bob.key_exchange(alice.public_key)
    alice.key_exchange(bob.public_key)
    msg1 = b'Hey Bob, how have you been?'
    cpt_from_alice = aes_cbc_encrypt(alice.shared_key, msg1)

    # Eve now knows shared_secret is either 1 or p-1, so only 1-2 attemps are required to decrypt cpts
    for secret in (1, captured_p-1):
        key = sha1(int_to_raw(secret), raw=True)[:16]
        try:
            decrypted_cpt = aes_cbc_decrypt(key, cpt_from_alice)
            eve_compromised_secret = secret
            eve_compromised_key = key
            break
        except Exception:  # possible cbc padding errors
            pass

    assert(decrypted_cpt == msg1)
    assert(alice.shared_key == bob.shared_key == eve_compromised_key)
    return True

def challenge36():
    # Implement Secure Remote Password (SRP)
    server = SRPServer()
    client1 = SRPClient('luis@teix.co', 'password')
    client2 = SRPClient('test@gmail.com', 'secret')
    client3 = SRPClient('luis@teix.co', 'wrongpassword')

    client1.key_exchange(*server.key_exchange(client1.email, client1.public_key))
    assert(server.authenticate(client1.email, client1.token))
    client2.key_exchange(*server.key_exchange(client2.email, client2.public_key))
    assert(server.authenticate(client2.email, client2.token))
    assert(not server.authenticate(client2.email, client1.token))
    assert(not server.authenticate(client1.email, client2.token))
    client3.key_exchange(*server.key_exchange(client3.email, client3.public_key))
    assert(not server.authenticate(client3.email, client3.token))
    return True

def challenge37():
    # Break SRP with a zero key

    server = SRPServer()
    email1 = 'luis@teix.co'
    email2 = 'test@gmail.com'

    # client_public_key = 0
    # shared_secret = 0 <= shared_secret = modexp(0, server_private_key, self.N) <= shared_secret = modexp((0 * modexp(v, u, N)), server_private_key, N)
    # shared_key = sha256(b'\x00', raw=True) => b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d'
    # token = hmac(b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d', salt, sha256) 
    salt, server_public_key = server.key_exchange('luis@teix.co', 0)
    fake_token = hmac(b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d', salt, sha256)
    assert(server.authenticate('luis@teix.co', fake_token))

    # client_public_key = N
    # shared_secret = modexp((N * modexp(v, u, self.N)), server_private_key, self.N); say modexp(v, u, self.N) = i and server_private_key = pk
    # shared_secret = modexp(N*i, pk, N) => shared_secret = 0  as (N*i)**pk will always be an increment of N, so (N*i)**pk % N = 0
    # Token is the same as client_public_key = 0

    salt, server_public_key = server.key_exchange('luis@teix.co', server.N)
    fake_token = hmac(b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d', salt, sha256)
    assert(server.authenticate('luis@teix.co', fake_token))

    # client_public_key = N**2
    # Token is the same as client_public_key = N
    salt, server_public_key = server.key_exchange('luis@teix.co', server.N**2)
    fake_token = hmac(b'n4\x0b\x9c\xff\xb3z\x98\x9c\xa5D\xe6\xbbx\n,x\x90\x1d?\xb378v\x85\x11\xa3\x06\x17\xaf\xa0\x1d', salt, sha256)
    assert(server.authenticate('luis@teix.co', fake_token))

    return True

def challenge38():
    # Offline dictionary attack on simplified SRP

    server = SimplifiedSRPServer()
    client1 = SimplifiedSRPClient('luis@teix.co', 'password')
    client2 = SimplifiedSRPClient('test@gmail.com', 'secret')
    client3 = SimplifiedSRPClient('luis@teix.co', 'wrongpassword')

    client1.key_exchange(*server.key_exchange(client1.email, client1.public_key))
    assert(server.authenticate(client1.email, client1.token))
    client2.key_exchange(*server.key_exchange(client2.email, client2.public_key))
    assert(server.authenticate(client2.email, client2.token))
    assert(not server.authenticate(client2.email, client1.token))
    assert(not server.authenticate(client1.email, client2.token))
    client3.key_exchange(*server.key_exchange(client3.email, client3.public_key))
    assert(not server.authenticate(client3.email, client3.token))

    # Dictionary attack below

    for victim in (SimplifiedSRPClient('victim1@gmail.com', 'abalone'), SimplifiedSRPClient('victim2@gmail.com', '8675309')):
        evil_salt = urandom(4)
        evil_u = raw_to_int(urandom(16))
        evil_private_key = raw_to_int(urandom(16)) % victim.N
        evil_public_key = modexp(victim.g, evil_private_key, victim.N)

        # victim calculates token based on attackers provided public key, salt and u 
        victim.key_exchange(evil_salt, evil_public_key, evil_u)
        attack_successful = False
        for word in open('/usr/share/dict/cracklib-small').read().splitlines():
            x = raw_to_int(sha256(evil_salt + ascii_to_raw(word), raw=True))
            v = modexp(victim.g, x, victim.N)
            shared_secret = modexp(victim.public_key * modexp(v, evil_u, victim.N), evil_private_key, victim.N)
            shared_key = sha256(int_to_raw(shared_secret), raw=True)
            if hmac(shared_key, evil_salt, sha256) == victim.token:
                attack_successful = True
                break
        assert(attack_successful)
    return True

def challenge39():
    # Implement RSA

    assert(modinv(17, 3120) == 2753)
    rsa = RSA()
    cpt = rsaencrypt('Super secret message', rsa.public_key, rsa.n)
    assert(rsadecrypt(cpt, rsa.private_key, rsa.n) == b'Super secret message')
    return True

def challenge40():
    # Implement an E=3 RSA Broadcast attack

    rsa0 = RSA()
    rsa1 = RSA()
    rsa2 = RSA()

    msg = b"same plaintext"
    cpt0 = rsaencrypt(msg, rsa0.public_key, rsa0.n)
    cpt1 = rsaencrypt(msg, rsa1.public_key, rsa1.n)
    cpt2 = rsaencrypt(msg, rsa2.public_key, rsa2.n)

    ms0 = rsa1.n * rsa2.n
    ms1 = rsa0.n * rsa2.n
    ms2 = rsa0.n * rsa1.n

    r = (cpt0 * ms0 * modinv(ms0, rsa0.n) + cpt1 * ms1 * modinv(ms1, rsa1.n) + cpt2 * ms2 * modinv(ms2, rsa2.n))
    cracked_msg = int_to_raw(find_cube_root(r % (rsa0.n * rsa1.n * rsa2.n)))
    assert(msg == cracked_msg)
    return True

if __name__ == '__main__':    
    print(challenge40())
