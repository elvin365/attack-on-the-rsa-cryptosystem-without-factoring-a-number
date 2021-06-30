import math
import random
from decimal import *
from Cryptodome.Util import number
from Cryptodome.Util.number import inverse
from sympy.ntheory.factor_ import factorint
from Cryptodome.Math.Primality import generate_probable_safe_prime as gen_safe_prime

esizes = {512: 10 ** 8, 768: 10 ** 10, 1024: 2 * 10 ** 11, 2048: 3 * 10 ** 15, 4096: 10 ** 21, 8192: 10 ** 29}


def get_esize(n):
    return esizes[n] if n in esizes else esizes[min(esizes.keys(), key=lambda k: abs(k - n))]


def gen_prime_test(bits):
    p = gen_safe_prime(exact_bits=bits)
    print(f"p is very good param {p}")
    return


def gen_prime(bits):
    while True:
        p = number.getStrongPrime(bits) # возвращает простое число
        factor = factorint(p - 1, 2 ** 15) # факторизация как проверка на простоту, с ограничением для ускорения
        print("HERE")
        if len(factor) <= 3:
            return p


def gen_relative_prime(low, up):
    a = random.randint(low, up)
    while a % 2 == 0 or math.gcd(a, up) != 1:
        a += 1
        if a >= up:
            a = random.randint(low, up)
    return a


def gen_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    low = get_esize(n)
    #limit = int(n ** (1 / 4) * 1 / 3)
    getcontext().prec = 650
    limit = int(Decimal(n)**(Decimal(1)/Decimal(4))*(Decimal(1)/Decimal(3)))
    while True:
        e = gen_relative_prime(low, phi)
        d = inverse(e, phi)
        if d > limit:
            return e, d, n
