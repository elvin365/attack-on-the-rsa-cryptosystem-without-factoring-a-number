import logging
import sys
from datetime import datetime
from logging import info
from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad, unpad

from gen_params import *
from ASN1 import *

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")

RSA_size = 512
d = 0x77E693EAA7C0DFD69AEB21130E0DF891178FA230CC906D095D06A1830164E4EF6375295EAA6A19FAD30E7BB4972FFBDB71A937AA2CEE3BC1ADA1C57B30A217A7
e = 0x35A362569BE3465B0FA287859CBA9DB13764C3DCE77853FC63734DCA752A6232838A4ED699C52F86649E695CDD8F09E76956985F67FA57D6FABD19C1CE3F9617
n = 0x78D8EFEF0A397FD92863E4C4DC70928B1EBACCE29FBBB3F8E661863461F56C0B31388ED75B31BDDA9712E2D0B595109483BC0096DF3F24ACC61CD527E7F0C52D


def len_in_bytes(a_: int):
    return math.ceil(math.floor(math.log2(n)) / 8)


class RSA:
    def __init__(self, N: int):
        self.N = N

    def genKeys(self):
        p = gen_prime(self.N)
        q = gen_prime(self.N)
        e, d, n = gen_keys(p, q)
        info(f"n = {n}\n"
             f"p = {p}\n"
             f"q = {q}\n"
             f"e = {e}\n"
             f"d = {d}\n")
        return n, e, d

    def encrypt(self, m, n, e):
        res = bytes()
        bs_enc = len_in_bytes(n)
        bs_pl = bs_enc - 1
        for i in range(0, len(m), bs_pl):
            t = int.from_bytes(m[i:i + bs_pl], 'big')
            c = pow(t, e, n)
            res += int(c).to_bytes(bs_enc, 'big')
        return res

    def decrypt(self, m, n, d, m_last_size):
        res = bytes()
        bs_enc = len_in_bytes(n)
        bs_pl = bs_enc - 1
        for i in range(0, len(m), bs_enc):
            t = int.from_bytes(m[i:i + bs_enc], 'big')
            c = pow(t, d, n)
            res += int(c).to_bytes(bs_pl, 'big')
        m_last_size = bs_pl if m_last_size % bs_pl == 0 else m_last_size % bs_pl
        res = res[:-bs_pl] + res[-m_last_size:]
        return res

    def sign(self, m, n, d):
        h = SHA256.new()
        h.update(m)
        r = h.digest()
        return self.encrypt(r, n, d)

    def verify(self, s, m, n, e):
        r = self.decrypt(s, n, e)
        h = SHA256.new()
        h.update(m)
        return int.from_bytes(r, 'big') == int.from_bytes(h.digest(), 'big')


def encAES(m):
    m = pad(m, 16)
    key = random.randint(1, 2 ** 256).to_bytes(32, 'big')
    iv = random.randint(1, 2 ** 128).to_bytes(16, 'big')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(m)
    return ciphertext, key, iv


def decAES(m, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(m)
    return unpad(plaintext, 16)


def P1enc(read_name, save_name):
    f = open(read_name, "rb")
    data = f.read()
    f.close()
    length = len(data)
    data, key, iv = encAES(data)
    rsa = RSA(RSA_size)
    # n, e, d = rsa.genKeys()
    enc_key = rsa.encrypt(key, n, e)
    data = packencASN1(n, e, int.from_bytes(enc_key, 'big'), int.from_bytes(iv, 'big'), length, "ecnrypted") + data
    f = open(save_name, "wb")
    f.write(data)
    f.close()
    info(f"File {read_name} was encrypted and saved to {save_name}")
    info(
        f"Used params:\nRSA modulus size = {RSA_size}\nn = {hex(n)}\ne = {hex(e)}\nn = {hex(n)}\nd = {hex(d)}\nAES key = {key.hex()}\nAES IV = {iv.hex()}")


def P1sign(read_name, save_name):
    f = open(read_name, "rb")
    data = f.read()
    f.close()
    rsa = RSA(RSA_size)
    # n, e, d = rsa.genKeys()
    s = rsa.sign(data, n, d)
    data = packsignASN1(n, e, int.from_bytes(s, 'big'), "signed") + data
    f = open(save_name, "wb")
    f.write(data)
    f.close()
    info(f"File {read_name} was signed and saved to {save_name}")


def P1dec(m, length, n, k, iv):
    rsa = RSA(RSA_size)
    k = rsa.decrypt(k.to_bytes(int(math.ceil(k.bit_length() / 8)), 'big'), n, d, 32)
    iv = iv.to_bytes(16, 'big')
    m = decAES(m, k, iv)
    return m


def P1ver(s, m, n, e):
    rsa = RSA(RSA_size)
    return rsa.verify(s.to_bytes(int(math.ceil(s.bit_length() / 8)), 'big'), m, n, e)


def P1dec_ver(read_name, save_name):
    f = open(read_name, "rb")
    data = f.read()
    f.close()
    header, data = parseASN1(data)
    alg = header[0]
    if alg == b'\x00\x01':
        info("RSA-AES algorith detected!")
        str_id = header[1]
        n = header[2]
        e = header[3]
        k = header[4]
        iv = header[6]
        length = header[7]
        data = P1dec(data, length, n, k, iv)
        f = open(save_name, "wb")
        f.write(data)
        f.close()
        info(f"File decrypted and saved to {save_name}!")
    elif alg == b'\x00\x40':
        info("RSA-SHA256 algorithm detected!")
        str_id = header[1]
        n = header[2]
        e = header[3]
        s = header[4]
        res = P1ver(s, data, n, e)
        info(f"Signature {'' if res == True else 'not '}verified!")
    else:
        info("Unknown algorithm! Terminating...")
        exit(0)


def main():
    random.seed(datetime.now())
    # rsa = RSA(RSA_size)
    # rsa.genKeys()
    if len(sys.argv) > 2:
        if sys.argv[1] == "sign" and len(sys.argv) == 4:
            P1sign(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == "verify" and len(sys.argv) == 4:
            P1dec_ver(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == "encrypt" and len(sys.argv) == 4:
            P1enc(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == "decrypt" and len(sys.argv) == 4:
            P1dec_ver(sys.argv[2], sys.argv[3])
        else:
            info("Unknown cmd args! Terminating...")
            exit(0)


main()
