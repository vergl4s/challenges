#!/usr/bin/env python3
import random
import string
from utils import *

def challenge17():
    key = Random.new().read(16)
    msgs = [b64_to_raw('MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc='),b64_to_raw('MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic='),b64_to_raw('MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=='),b64_to_raw('MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=='),b64_to_raw('MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl'),b64_to_raw('MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=='),b64_to_raw('MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=='),b64_to_raw('MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8='),b64_to_raw('MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g='),b64_to_raw('MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93')]

    def produce_cookie(msg):
        # return aes_cbc_encrypt(key, random.choice(msgs))
        return aes_cbc_encrypt(key, msg)

    def padding_oracle(cookie):
        try:
            aes_cbc_decrypt(key, cookie)  # should raise a ValueError if there's bad padding
            return True
        except ValueError:
            return False
    
    def brute_force_padding(cpt1, cpt2):

        intermediate_msg2 = [0] * 16
        temp_cpt1 = list(Random.new().read(16))

        for i in range(1,17):

            # adjusts already known intermediate values to be i, i.e. the right padding
            for k in range(1, i):
                temp_cpt1[-k] = intermediate_msg2[-k] ^ i

            # brute forces next unknown intermediate value
            for j in range(256):
                temp_cpt1[-i] = j
                if padding_oracle(bytes(temp_cpt1)+bytes(cpt2)):
                    # print("{}, {}".format(i, j))
                    intermediate_msg2[-i] = j ^ i
                    break

        return fixed_xor(cpt1, intermediate_msg2)

    decrypted_cookies = []
    for msg in msgs:
        cookie = break_raw_into_chunks(produce_cookie(msg), 16)
        decrypted_cookies.append(b''.join([brute_force_padding(list(cookie[i]),list(cookie[i+1])) for i,v in enumerate(cookie[:-1])]))
    return msgs

def challenge18():
    # Implement CTR, the stream cipher mode

    cpt = b64_to_raw('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    counter = Counter.new(8*8, initial_value = 0, little_endian=True, prefix=b'\x00'*8)
    return aes_ctr_encrypt('YELLOW SUBMARINE', cpt, counter)

    # Coursera week 2 CTR
    # key1, cpt1 = hex_to_raw('36f18357be4dbd77f050515c73fcf9f2'), hex_to_raw('69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
    # ctr1, cpt1 = Counter.new(128, initial_value=int.from_bytes(cpt1[:16], 'big')), cpt1[16:]
    # key2, cpt2 = hex_to_raw('36f18357be4dbd77f050515c73fcf9f2'), hex_to_raw('770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
    # ctr2, cpt2 = Counter.new(128, initial_value=int.from_bytes(cpt2[:16], 'big')), cpt2[16:]
    # print(aes_ctr_encrypt(key1, cpt1, ctr1))
    # print(aes_ctr_encrypt(key2, cpt2, ctr2))
    
def challenge19():
    # Break fixed-nonce CTR mode using substitions
    
    # Example of different CTR counters
    # common_counters_imo = [ctr for sublist in [
    #     [Counter.new(8*8, little_endian=True, initial_value = i, prefix=b'\x00'*8) for i in range(16)],
    #     [Counter.new(128, little_endian=False, initial_value=i) for i in range(16)],
    #     [Counter.new(128, little_endian=True, initial_value=i) for i in range(16)],
    #     [Counter.new(128, little_endian=False, initial_value=int.from_bytes(ascii_to_raw(c*16),'big')) for c in string.printable],
    #     [Counter.new(128, little_endian=True, initial_value=int.from_bytes(ascii_to_raw(c*16),'big')) for c in string.printable],
    # ] for ctr in sublist]

    key = Random.new().read(16)
    msgs = [b64_to_raw('SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ=='),b64_to_raw('Q29taW5nIHdpdGggdml2aWQgZmFjZXM='),b64_to_raw('RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ=='),b64_to_raw('RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4='),b64_to_raw('SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk'),b64_to_raw('T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=='),b64_to_raw('T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ='),b64_to_raw('UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA=='),b64_to_raw('QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU='),b64_to_raw('T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl'),b64_to_raw('VG8gcGxlYXNlIGEgY29tcGFuaW9u'),b64_to_raw('QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA=='),b64_to_raw('QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk='),b64_to_raw('QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg=='),b64_to_raw('QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo='),b64_to_raw('QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='),b64_to_raw('VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA=='),b64_to_raw('SW4gaWdub3JhbnQgZ29vZCB3aWxsLA=='),b64_to_raw('SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA=='),b64_to_raw('VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg=='),b64_to_raw('V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw=='),b64_to_raw('V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA=='),b64_to_raw('U2hlIHJvZGUgdG8gaGFycmllcnM/'),b64_to_raw('VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w='),b64_to_raw('QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4='),b64_to_raw('VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ='),b64_to_raw('V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs='),b64_to_raw('SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA=='),b64_to_raw('U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA=='),b64_to_raw('U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4='),b64_to_raw('VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA=='),b64_to_raw('QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu'),b64_to_raw('SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc='),b64_to_raw('VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs'),b64_to_raw('WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs='),b64_to_raw('SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0'),b64_to_raw('SW4gdGhlIGNhc3VhbCBjb21lZHk7'),b64_to_raw('SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw='),b64_to_raw('VHJhbnNmb3JtZWQgdXR0ZXJseTo='),b64_to_raw('QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='),]
    cpts = [aes_ctr_encrypt(key, m, Counter.new(8*8, initial_value = 0, little_endian=True, prefix=b'\x00'*8)) for m in msgs]
    keystream = []
    # Will break keystream one byte at a time by brute forcing possible keystream bytes between 0x00 and 0xff
    for encrypted_bytes in transpose_blocks(cpts):
        score = {}
        for i in range(255):
            score[i] = score_plaintext(''.join([chr(i^byte) for byte in encrypted_bytes]))
        keystream.append(sorted(score.items(), key=lambda x: x[1])[-1][0])

    # had good results up to byte 19, although it was a bit inconsistent with capitalization and whitespaces
    # PS was winging this one through without realizing it is exactly like challenge 3
    decrypted_msgs = [fixed_xor(keystream[:len(cpt)], cpt) for cpt in cpts]
    return decrypted_msgs
    # return True

def challenge20():
    # Break fixed-nonce CTR statistically

    key = Random.new().read(16)
    msgs = [b64_to_raw('SSdtIHJhdGVkICJSIi4uLnRoaXMgaXMgYSB3YXJuaW5nLCB5YSBiZXR0ZXIgdm9pZCAvIFBvZXRzIGFyZSBwYXJhbm9pZCwgREoncyBELXN0cm95ZWQ='),b64_to_raw('Q3V6IEkgY2FtZSBiYWNrIHRvIGF0dGFjayBvdGhlcnMgaW4gc3BpdGUtIC8gU3RyaWtlIGxpa2UgbGlnaHRuaW4nLCBJdCdzIHF1aXRlIGZyaWdodGVuaW4nIQ=='),b64_to_raw('QnV0IGRvbid0IGJlIGFmcmFpZCBpbiB0aGUgZGFyaywgaW4gYSBwYXJrIC8gTm90IGEgc2NyZWFtIG9yIGEgY3J5LCBvciBhIGJhcmssIG1vcmUgbGlrZSBhIHNwYXJrOw=='),b64_to_raw('WWEgdHJlbWJsZSBsaWtlIGEgYWxjb2hvbGljLCBtdXNjbGVzIHRpZ2h0ZW4gdXAgLyBXaGF0J3MgdGhhdCwgbGlnaHRlbiB1cCEgWW91IHNlZSBhIHNpZ2h0IGJ1dA=='),b64_to_raw('U3VkZGVubHkgeW91IGZlZWwgbGlrZSB5b3VyIGluIGEgaG9ycm9yIGZsaWNrIC8gWW91IGdyYWIgeW91ciBoZWFydCB0aGVuIHdpc2ggZm9yIHRvbW9ycm93IHF1aWNrIQ=='),b64_to_raw('TXVzaWMncyB0aGUgY2x1ZSwgd2hlbiBJIGNvbWUgeW91ciB3YXJuZWQgLyBBcG9jYWx5cHNlIE5vdywgd2hlbiBJJ20gZG9uZSwgeWEgZ29uZSE='),b64_to_raw('SGF2ZW4ndCB5b3UgZXZlciBoZWFyZCBvZiBhIE1DLW11cmRlcmVyPyAvIFRoaXMgaXMgdGhlIGRlYXRoIHBlbmFsdHksYW5kIEknbSBzZXJ2aW4nIGE='),b64_to_raw('RGVhdGggd2lzaCwgc28gY29tZSBvbiwgc3RlcCB0byB0aGlzIC8gSHlzdGVyaWNhbCBpZGVhIGZvciBhIGx5cmljYWwgcHJvZmVzc2lvbmlzdCE='),b64_to_raw('RnJpZGF5IHRoZSB0aGlydGVlbnRoLCB3YWxraW5nIGRvd24gRWxtIFN0cmVldCAvIFlvdSBjb21lIGluIG15IHJlYWxtIHlhIGdldCBiZWF0IQ=='),b64_to_raw('VGhpcyBpcyBvZmYgbGltaXRzLCBzbyB5b3VyIHZpc2lvbnMgYXJlIGJsdXJyeSAvIEFsbCB5YSBzZWUgaXMgdGhlIG1ldGVycyBhdCBhIHZvbHVtZQ=='),b64_to_raw('VGVycm9yIGluIHRoZSBzdHlsZXMsIG5ldmVyIGVycm9yLWZpbGVzIC8gSW5kZWVkIEknbSBrbm93bi15b3VyIGV4aWxlZCE='),b64_to_raw('Rm9yIHRob3NlIHRoYXQgb3Bwb3NlIHRvIGJlIGxldmVsIG9yIG5leHQgdG8gdGhpcyAvIEkgYWluJ3QgYSBkZXZpbCBhbmQgdGhpcyBhaW4ndCB0aGUgRXhvcmNpc3Qh'),b64_to_raw('V29yc2UgdGhhbiBhIG5pZ2h0bWFyZSwgeW91IGRvbid0IGhhdmUgdG8gc2xlZXAgYSB3aW5rIC8gVGhlIHBhaW4ncyBhIG1pZ3JhaW5lIGV2ZXJ5IHRpbWUgeWEgdGhpbms='),b64_to_raw('Rmxhc2hiYWNrcyBpbnRlcmZlcmUsIHlhIHN0YXJ0IHRvIGhlYXI6IC8gVGhlIFItQS1LLUktTSBpbiB5b3VyIGVhcjs='),b64_to_raw('VGhlbiB0aGUgYmVhdCBpcyBoeXN0ZXJpY2FsIC8gVGhhdCBtYWtlcyBFcmljIGdvIGdldCBhIGF4IGFuZCBjaG9wcyB0aGUgd2Fjaw=='),b64_to_raw('U29vbiB0aGUgbHlyaWNhbCBmb3JtYXQgaXMgc3VwZXJpb3IgLyBGYWNlcyBvZiBkZWF0aCByZW1haW4='),b64_to_raw('TUMncyBkZWNheWluZywgY3V6IHRoZXkgbmV2ZXIgc3RheWVkIC8gVGhlIHNjZW5lIG9mIGEgY3JpbWUgZXZlcnkgbmlnaHQgYXQgdGhlIHNob3c='),b64_to_raw('VGhlIGZpZW5kIG9mIGEgcmh5bWUgb24gdGhlIG1pYyB0aGF0IHlvdSBrbm93IC8gSXQncyBvbmx5IG9uZSBjYXBhYmxlLCBicmVha3MtdGhlIHVuYnJlYWthYmxl'),b64_to_raw('TWVsb2RpZXMtdW5tYWthYmxlLCBwYXR0ZXJuLXVuZXNjYXBhYmxlIC8gQSBob3JuIGlmIHdhbnQgdGhlIHN0eWxlIEkgcG9zc2Vz'),b64_to_raw('SSBibGVzcyB0aGUgY2hpbGQsIHRoZSBlYXJ0aCwgdGhlIGdvZHMgYW5kIGJvbWIgdGhlIHJlc3QgLyBGb3IgdGhvc2UgdGhhdCBlbnZ5IGEgTUMgaXQgY2FuIGJl'),b64_to_raw('SGF6YXJkb3VzIHRvIHlvdXIgaGVhbHRoIHNvIGJlIGZyaWVuZGx5IC8gQSBtYXR0ZXIgb2YgbGlmZSBhbmQgZGVhdGgsIGp1c3QgbGlrZSBhIGV0Y2gtYS1za2V0Y2g='),b64_to_raw('U2hha2UgJ3RpbGwgeW91ciBjbGVhciwgbWFrZSBpdCBkaXNhcHBlYXIsIG1ha2UgdGhlIG5leHQgLyBBZnRlciB0aGUgY2VyZW1vbnksIGxldCB0aGUgcmh5bWUgcmVzdCBpbiBwZWFjZQ=='),b64_to_raw('SWYgbm90LCBteSBzb3VsJ2xsIHJlbGVhc2UhIC8gVGhlIHNjZW5lIGlzIHJlY3JlYXRlZCwgcmVpbmNhcm5hdGVkLCB1cGRhdGVkLCBJJ20gZ2xhZCB5b3UgbWFkZSBpdA=='),b64_to_raw('Q3V6IHlvdXIgYWJvdXQgdG8gc2VlIGEgZGlzYXN0cm91cyBzaWdodCAvIEEgcGVyZm9ybWFuY2UgbmV2ZXIgYWdhaW4gcGVyZm9ybWVkIG9uIGEgbWljOg=='),b64_to_raw('THlyaWNzIG9mIGZ1cnkhIEEgZmVhcmlmaWVkIGZyZWVzdHlsZSEgLyBUaGUgIlIiIGlzIGluIHRoZSBob3VzZS10b28gbXVjaCB0ZW5zaW9uIQ=='),b64_to_raw('TWFrZSBzdXJlIHRoZSBzeXN0ZW0ncyBsb3VkIHdoZW4gSSBtZW50aW9uIC8gUGhyYXNlcyB0aGF0J3MgZmVhcnNvbWU='),b64_to_raw('WW91IHdhbnQgdG8gaGVhciBzb21lIHNvdW5kcyB0aGF0IG5vdCBvbmx5IHBvdW5kcyBidXQgcGxlYXNlIHlvdXIgZWFyZHJ1bXM7IC8gSSBzaXQgYmFjayBhbmQgb2JzZXJ2ZSB0aGUgd2hvbGUgc2NlbmVyeQ=='),b64_to_raw('VGhlbiBub25jaGFsYW50bHkgdGVsbCB5b3Ugd2hhdCBpdCBtZWFuIHRvIG1lIC8gU3RyaWN0bHkgYnVzaW5lc3MgSSdtIHF1aWNrbHkgaW4gdGhpcyBtb29k'),b64_to_raw('QW5kIEkgZG9uJ3QgY2FyZSBpZiB0aGUgd2hvbGUgY3Jvd2QncyBhIHdpdG5lc3MhIC8gSSdtIGEgdGVhciB5b3UgYXBhcnQgYnV0IEknbSBhIHNwYXJlIHlvdSBhIGhlYXJ0'),b64_to_raw('UHJvZ3JhbSBpbnRvIHRoZSBzcGVlZCBvZiB0aGUgcmh5bWUsIHByZXBhcmUgdG8gc3RhcnQgLyBSaHl0aG0ncyBvdXQgb2YgdGhlIHJhZGl1cywgaW5zYW5lIGFzIHRoZSBjcmF6aWVzdA=='),b64_to_raw('TXVzaWNhbCBtYWRuZXNzIE1DIGV2ZXIgbWFkZSwgc2VlIGl0J3MgLyBOb3cgYW4gZW1lcmdlbmN5LCBvcGVuLWhlYXJ0IHN1cmdlcnk='),b64_to_raw('T3BlbiB5b3VyIG1pbmQsIHlvdSB3aWxsIGZpbmQgZXZlcnkgd29yZCdsbCBiZSAvIEZ1cmllciB0aGFuIGV2ZXIsIEkgcmVtYWluIHRoZSBmdXJ0dXJl'),b64_to_raw('QmF0dGxlJ3MgdGVtcHRpbmcuLi53aGF0ZXZlciBzdWl0cyB5YSEgLyBGb3Igd29yZHMgdGhlIHNlbnRlbmNlLCB0aGVyZSdzIG5vIHJlc2VtYmxhbmNl'),b64_to_raw('WW91IHRoaW5rIHlvdSdyZSBydWZmZXIsIHRoZW4gc3VmZmVyIHRoZSBjb25zZXF1ZW5jZXMhIC8gSSdtIG5ldmVyIGR5aW5nLXRlcnJpZnlpbmcgcmVzdWx0cw=='),b64_to_raw('SSB3YWtlIHlhIHdpdGggaHVuZHJlZHMgb2YgdGhvdXNhbmRzIG9mIHZvbHRzIC8gTWljLXRvLW1vdXRoIHJlc3VzY2l0YXRpb24sIHJoeXRobSB3aXRoIHJhZGlhdGlvbg=='),b64_to_raw('Tm92b2NhaW4gZWFzZSB0aGUgcGFpbiBpdCBtaWdodCBzYXZlIGhpbSAvIElmIG5vdCwgRXJpYyBCLidzIHRoZSBqdWRnZSwgdGhlIGNyb3dkJ3MgdGhlIGp1cnk='),b64_to_raw('WW8gUmFraW0sIHdoYXQncyB1cD8gLyBZbywgSSdtIGRvaW5nIHRoZSBrbm93bGVkZ2UsIEUuLCBtYW4gSSdtIHRyeWluZyB0byBnZXQgcGFpZCBpbiBmdWxs'),b64_to_raw('V2VsbCwgY2hlY2sgdGhpcyBvdXQsIHNpbmNlIE5vcmJ5IFdhbHRlcnMgaXMgb3VyIGFnZW5jeSwgcmlnaHQ/IC8gVHJ1ZQ=='),b64_to_raw('S2FyYSBMZXdpcyBpcyBvdXIgYWdlbnQsIHdvcmQgdXAgLyBaYWtpYSBhbmQgNHRoIGFuZCBCcm9hZHdheSBpcyBvdXIgcmVjb3JkIGNvbXBhbnksIGluZGVlZA=='),b64_to_raw('T2theSwgc28gd2hvIHdlIHJvbGxpbicgd2l0aCB0aGVuPyBXZSByb2xsaW4nIHdpdGggUnVzaCAvIE9mIFJ1c2h0b3duIE1hbmFnZW1lbnQ='),b64_to_raw('Q2hlY2sgdGhpcyBvdXQsIHNpbmNlIHdlIHRhbGtpbmcgb3ZlciAvIFRoaXMgZGVmIGJlYXQgcmlnaHQgaGVyZSB0aGF0IEkgcHV0IHRvZ2V0aGVy'),b64_to_raw('SSB3YW5uYSBoZWFyIHNvbWUgb2YgdGhlbSBkZWYgcmh5bWVzLCB5b3Uga25vdyB3aGF0IEknbSBzYXlpbic/IC8gQW5kIHRvZ2V0aGVyLCB3ZSBjYW4gZ2V0IHBhaWQgaW4gZnVsbA=='),b64_to_raw('VGhpbmtpbicgb2YgYSBtYXN0ZXIgcGxhbiAvICdDdXogYWluJ3QgbnV0aGluJyBidXQgc3dlYXQgaW5zaWRlIG15IGhhbmQ='),b64_to_raw('U28gSSBkaWcgaW50byBteSBwb2NrZXQsIGFsbCBteSBtb25leSBpcyBzcGVudCAvIFNvIEkgZGlnIGRlZXBlciBidXQgc3RpbGwgY29taW4nIHVwIHdpdGggbGludA=='),b64_to_raw('U28gSSBzdGFydCBteSBtaXNzaW9uLCBsZWF2ZSBteSByZXNpZGVuY2UgLyBUaGlua2luJyBob3cgY291bGQgSSBnZXQgc29tZSBkZWFkIHByZXNpZGVudHM='),b64_to_raw('SSBuZWVkIG1vbmV5LCBJIHVzZWQgdG8gYmUgYSBzdGljay11cCBraWQgLyBTbyBJIHRoaW5rIG9mIGFsbCB0aGUgZGV2aW91cyB0aGluZ3MgSSBkaWQ='),b64_to_raw('SSB1c2VkIHRvIHJvbGwgdXAsIHRoaXMgaXMgYSBob2xkIHVwLCBhaW4ndCBudXRoaW4nIGZ1bm55IC8gU3RvcCBzbWlsaW5nLCBiZSBzdGlsbCwgZG9uJ3QgbnV0aGluJyBtb3ZlIGJ1dCB0aGUgbW9uZXk='),b64_to_raw('QnV0IG5vdyBJIGxlYXJuZWQgdG8gZWFybiAnY3V6IEknbSByaWdodGVvdXMgLyBJIGZlZWwgZ3JlYXQsIHNvIG1heWJlIEkgbWlnaHQganVzdA=='),b64_to_raw('U2VhcmNoIGZvciBhIG5pbmUgdG8gZml2ZSwgaWYgSSBzdHJpdmUgLyBUaGVuIG1heWJlIEknbGwgc3RheSBhbGl2ZQ=='),b64_to_raw('U28gSSB3YWxrIHVwIHRoZSBzdHJlZXQgd2hpc3RsaW4nIHRoaXMgLyBGZWVsaW4nIG91dCBvZiBwbGFjZSAnY3V6LCBtYW4sIGRvIEkgbWlzcw=='),b64_to_raw('QSBwZW4gYW5kIGEgcGFwZXIsIGEgc3RlcmVvLCBhIHRhcGUgb2YgLyBNZSBhbmQgRXJpYyBCLCBhbmQgYSBuaWNlIGJpZyBwbGF0ZSBvZg=='),b64_to_raw('RmlzaCwgd2hpY2ggaXMgbXkgZmF2b3JpdGUgZGlzaCAvIEJ1dCB3aXRob3V0IG5vIG1vbmV5IGl0J3Mgc3RpbGwgYSB3aXNo'),b64_to_raw('J0N1eiBJIGRvbid0IGxpa2UgdG8gZHJlYW0gYWJvdXQgZ2V0dGluJyBwYWlkIC8gU28gSSBkaWcgaW50byB0aGUgYm9va3Mgb2YgdGhlIHJoeW1lcyB0aGF0IEkgbWFkZQ=='),b64_to_raw('U28gbm93IHRvIHRlc3QgdG8gc2VlIGlmIEkgZ290IHB1bGwgLyBIaXQgdGhlIHN0dWRpbywgJ2N1eiBJJ20gcGFpZCBpbiBmdWxs'),b64_to_raw('UmFraW0sIGNoZWNrIHRoaXMgb3V0LCB5byAvIFlvdSBnbyB0byB5b3VyIGdpcmwgaG91c2UgYW5kIEknbGwgZ28gdG8gbWluZQ=='),b64_to_raw('J0NhdXNlIG15IGdpcmwgaXMgZGVmaW5pdGVseSBtYWQgLyAnQ2F1c2UgaXQgdG9vayB1cyB0b28gbG9uZyB0byBkbyB0aGlzIGFsYnVt'),b64_to_raw('WW8sIEkgaGVhciB3aGF0IHlvdSdyZSBzYXlpbmcgLyBTbyBsZXQncyBqdXN0IHB1bXAgdGhlIG11c2ljIHVw'),b64_to_raw('QW5kIGNvdW50IG91ciBtb25leSAvIFlvLCB3ZWxsIGNoZWNrIHRoaXMgb3V0LCB5byBFbGk='),b64_to_raw('VHVybiBkb3duIHRoZSBiYXNzIGRvd24gLyBBbmQgbGV0IHRoZSBiZWF0IGp1c3Qga2VlcCBvbiByb2NraW4n'),b64_to_raw('QW5kIHdlIG91dHRhIGhlcmUgLyBZbywgd2hhdCBoYXBwZW5lZCB0byBwZWFjZT8gLyBQZWFjZQ=='),]
    cpts = [aes_ctr_encrypt(key, m, Counter.new(8*8, initial_value = 0, little_endian=True, prefix=b'\x00'*8)) for m in msgs]

    keystream = [single_char_xor_bruteforce(transposed_cpt) for transposed_cpt in transpose_blocks(cpts)]

    return [fixed_xor(cpt, keystream[:len(cpt)]) for cpt in cpts]

if __name__ == '__main__':
    print(challenge19())

