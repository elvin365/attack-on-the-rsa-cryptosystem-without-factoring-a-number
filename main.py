import logging
import random
import math
import sys
from Cryptodome.Util.number import inverse
from datetime import datetime
from logging import info
from gen_params import *
from main1 import RSA

logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")


def Alg2_1(n, ea, eb, db):
    N = eb * db - 1
    f = 0
    s = N
    while s % 2 == 0:
        f += 1
        s //= 2
    while True:
        a = random.randint(2, n)
        b = pow(a, s, n)
        t = b
        b = pow(b, 2, n)
        while b != 1:
            t = b
            b = pow(b, 2, n)
        if t != n - 1:
            break
    p = math.gcd(t + 1, n) # (4)
    q = math.gcd(t - 1, n) # (4)
    phi = (p - 1) * (q - 1)
    d = inverse(ea, phi) # d=e^(-1)mod n
    return p, q, d


def contFrac(n, d):
    cf = []
    while True:
        cf.append(n // d)
        rem = n % d
        n = d
        d = rem
        if d == 0:
            break
    return cf


def wiener(n, e):
    m = random.randint(2, n)
    me = pow(m, e, n)
    cf = contFrac(e, n)
    cf = cf[1:]
    Q_1 = 0
    Q_0 = 1
    for a in cf:
        Q = a * Q_0 + Q_1
        m1 = pow(me, Q, n)
        if m1 == m:
            return Q
        Q_1 = Q_0
        Q_0 = Q
    return -1


def Alg2_4(n, c, e):
    c0 = c
    while True:
        cprev = c
        c = pow(c, e, n)
        if c == c0:
            return int(cprev)


def main():
    #gen_prime_test(256)
    #gen_prime_test(512)
    #gen_prime_test(1024)
    #gen_prime_test(2048)

    db = 0x77E693EAA7C0DFD69AEB21130E0DF891178FA230CC906D095D06A1830164E4EF6375295EAA6A19FAD30E7BB4972FFBDB71A937AA2CEE3BC1ADA1C57B30A217A7
    eb = 0x35A362569BE3465B0FA287859CBA9DB13764C3DCE77853FC63734DCA752A6232838A4ED699C52F86649E695CDD8F09E76956985F67FA57D6FABD19C1CE3F9617
    n = 0x78D8EFEF0A397FD92863E4C4DC70928B1EBACCE29FBBB3F8E661863461F56C0B31388ED75B31BDDA9712E2D0B595109483BC0096DF3F24ACC61CD527E7F0C52D

    ea = 5685263797886913133055847610347187504480134889004652024264626436304933782114662123911569869356533305197344321092228167848937365536641903309711355548938559
    da = 5226817542677159244553252195007976004700966434512429664764434720961625989142294250652544960709510363258991954113748694974976144452897286512889855916603071

    ec = 3797575492591847160166531613910594781660890857981463889314985346172721230652388858388733802861236016930543825262888128179555525095674526709832617718246093
    dc = 5
    random.seed(datetime.now())
    info("Start")
    info(f"n = {hex(n)}\nea = {hex(ea)}\neb = {hex(eb)}\ndb = {hex(db)}")
    p, q, da1 = Alg2_1(n, ea, eb, db)
    info(f"p = {hex(p)}\nq = {hex(q)}\np*q = {hex(p * q)} {p * q == n}\nda = {hex(da1)}\nda==da1 -> {da == da1}")
#------------------------------------2
    print("wiener")
    dc = 2
    while math.gcd(dc, (p - 1) * (q - 1)) != 1:
        dc = random.randint(0.1 * n ** (1 / 4), 0.3 * n ** (1 / 4))
    ec = inverse(dc, (p - 1) * (q - 1))
    info(f"check {pow(pow(5, dc, n), ec, n)}")
    info(f"dc = {dc}\nec = {ec}")

    dc1 = wiener(n, ec)
    info(f"dc1 = {dc1} {dc == dc1}")
#-----------------------------------2

#-----------------------------3
    #m = 346#2#234913748356
    m = 123456#2#234913748356
    #n1=61*53
    n1=983*563
    e=49
    c = pow(m, e, n1)
    m2 = Alg2_4(n1, c, e)
    info(f"m2 = {m2} {m == m2}")
#----------------------------3

    q1 = gen_prime(2048)
    p1 = gen_prime(2048)
    #p1 = 11805639674883327389697576828531382092379989958487602683441100520350303251334412940606356298195506804331004286195037100488503367678093787202514691966774577
    #q1 = 11389982538815619941440368107386417795256506064244111841928907833067376651190762898414040405242336151354943488105465521902170088901777994439235249111825869
    info(f"good params\np = {hex(p1)}\nq = {hex(q1)}\nn = {hex(p1 * q1)}")
    ea, da, n = gen_keys(p1, q1)
    eb, db, n = gen_keys(p1, q1)
    info(f"ea = {hex(ea)}\nda = {hex(da)}\neb = {hex(eb)}\ndb = {hex(db)}\n")
    info(f"eb!=ea {eb != ea}")
    info(f"db!=da {db != da}")

    #p, q, da1 = Alg2_1(n, ea, eb, db)
    #info(f"p = {p}\nq = {q}\np*q = {p * q} {p * q == n}\nda = {da1}\nda==da1 -> {da == da1}")

    #dc1 = wiener(n, ec)
    #info(f"dc1 = {dc1} {dc == dc1}")


main()
