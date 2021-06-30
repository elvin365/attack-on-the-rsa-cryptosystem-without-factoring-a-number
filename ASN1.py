import logging
from logging import info
import math
import sys

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")

def ASN1packlen(length: int):
    r = b''
    if length < 128:
        r += length.to_bytes(1, 'big')
    else:
        t = int(math.ceil(length.bit_length() / 8))
        r += (t + 0x80).to_bytes(1, 'big') + length.to_bytes(t, 'big')
    return r


def ASN1packstr(a: str):
    a = str.encode(a, 'utf-8')
    length = len(a)
    r = b'\x0c'
    r += ASN1packlen(length)
    r += a
    return r


def ASN1packbytes(a: bytes):
    length = len(a)
    r = b'\x04'
    r += ASN1packlen(length)
    r += a
    return r


def ASN1packint(a: int):
    length = int(math.ceil(a.bit_length() / 8))
    r = b'\x02'
    if a & 2 ** (length * 8 - 1) != 0:
        length += 1
    r += ASN1packlen(length)
    r += a.to_bytes(length, 'big')
    return r


def ASN1packseq(A: list):
    r = b''
    length = 0
    for a in A:
        r += a
        length += len(a)
    r = b'\x30' + ASN1packlen(length) + r
    return r


def ASN1packset(A: list):
    r = b''
    length = 0
    for a in A:
        r += a
        length += len(a)
    r = b'\x31' + ASN1packlen(length) + r
    return r


def packsignASN1(n, e, s, str_id):
    str_id = ASN1packstr(str_id)
    n = ASN1packint(n)
    e = ASN1packint(e)
    RSAblock = ASN1packseq(
        [ASN1packbytes(b'\x00\x40'), str_id, ASN1packseq([n, e]), ASN1packseq([]), ASN1packseq([ASN1packint(s)])])
    return ASN1packseq([ASN1packset([RSAblock]), ASN1packseq([])])

def packELsignASN1(w, s, b, p, r, a, str_id):
    str_id = ASN1packstr(str_id)
    w = ASN1packint(w)
    s = ASN1packint(s)
    b = ASN1packint(b)
    p = ASN1packint(p)
    r = ASN1packint(r)
    a = ASN1packint(a)
    EL_signature = ASN1packseq([w, s])
    EL_key = ASN1packseq([b])
    EL_params = ASN1packseq([p, r, a])
    EL_block = ASN1packseq(
        [ASN1packbytes(b'\x80\x06\x02\x00'), str_id, EL_key, EL_params, EL_signature])
    return ASN1packseq([ASN1packset([EL_block]), ASN1packseq([])])


def packencASN1(n, e, k, iv, mlen, str_id):
    str_id = ASN1packstr(str_id)
    n = ASN1packint(n)
    e = ASN1packint(e)
    RSAblock = ASN1packseq(
        [ASN1packbytes(b'\x00\x01'), str_id, ASN1packseq([n, e]), ASN1packseq([]), ASN1packseq([ASN1packint(k)])])
    AESblock = ASN1packseq([ASN1packbytes(b'\x10\x82'), ASN1packint(iv), ASN1packint(mlen)])
    return ASN1packseq([ASN1packset([RSAblock]), AESblock])


def parseASN1impl(m: bytes):
    ret = []
    while len(m) > 0:
        elem_type = m[0]
        m = m[1:]
        if int(m[0]) < 128:
            length = int(m[0])
            elem = m[1:length + 1]
            m = m[length + 1:]
        else:
            ll = int(m[0]) - 128
            length = int.from_bytes(m[1:ll + 1], 'big')
            elem = m[ll + 1:ll + 1 + length]
            m = m[ll + 1 + length:]
        if elem_type == 0x02:
            elem = int.from_bytes(elem, 'big')
        elif elem_type == 0x0c:
            elem = elem.decode('utf-8')
        elif elem_type == 0x04:
            elem = elem
        elif elem_type == 0x30 or elem_type == 0x31:
            elem = parseASN1impl(elem)
            if elem:
                ret += elem
            continue
        else:
            info("ASN1: Unsuppotred type! Terminating...")
            exit(0)
        ret.append(elem)
    if len(m) > 0:
        info("ASN1: Extra data detected! Terminating...")
        exit(0)
    else:
        return ret


def parseASN1(m: bytes):
    ret = []
    elem_type = m[0]
    m = m[1:]
    if int(m[0]) < 128:
        length = int(m[0])
        elem = m[1:length + 1]
        m = m[length + 1:]
    else:
        ll = int(m[0]) - 128
        length = int.from_bytes(m[1:ll + 1], 'big')
        elem = m[ll + 1:ll + 1 + length]
        m = m[ll + 1 + length:]
    if elem_type == 0x02:
        elem = int.from_bytes(elem, 'big')
    elif elem_type == 0x0c:
        elem = elem.decode('utf-8')
    elif elem_type == 0x04:
        elem = elem
    elif elem_type == 0x30 or elem_type == 0x31:
        elem = parseASN1impl(elem)
        if elem:
            ret += elem
    else:
        info("ASN1: Unsuppotred type!")
        exit(0)
    if len(m) > 0:
        return ret, m
    else:
        return ret, None
