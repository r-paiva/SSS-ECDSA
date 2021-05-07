from ecdsa import EllipticCurve
from modular_inverse import euclideans_algorithm
import hashlib
import binascii


print "#### THIS IS A TEST ####"

available_curves = {}

secp256r1_list = [
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,  # a
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,  # b
    0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,  # p
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,  # gx
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,  # gy
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,  # n
    1  # h
]

available_curves["secp256r1"] = secp256r1_list

demo_curve = EllipticCurve(2, 2, 17, 5, 1, 18, 1)
m = demo_curve.multiply(16, demo_curve.getGPoint())

print "################################################\n\n\n"
print "THIS TEST IS FROM THE SUITE B IMPLEMENTERS GUIDE TO FIPS 186-3 FROM NIST. The values that i am using here can be found"
print "on appendix D of the following pdf."
print "https://www.nsa.gov/ia/_files/ecdsa.pdf\n\n\n"
print "################################################"

print available_curves.get("secp256r1")
secp256_dparameters = available_curves.get("secp256r1")
print "a ", secp256_dparameters[0]
print "b ", secp256_dparameters[1]
print "p ", secp256_dparameters[2]
print "gx ", secp256_dparameters[3]
print "gy ", secp256_dparameters[4]
print "n ", secp256_dparameters[5]
print "h ", secp256_dparameters[6]
print "a ", hex(secp256_dparameters[0])
print "b ", hex(secp256_dparameters[1])
print "p ", hex(secp256_dparameters[2])
print "gx ", hex(secp256_dparameters[3])
print "gy ", hex(secp256_dparameters[4])
print "n ", hex(secp256_dparameters[5])
print "h ", hex(secp256_dparameters[6])


print "TESTING DOMAIN PARAMETERS"
print "a -> ", secp256_dparameters[0] == 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
print "b -> ", secp256_dparameters[1] == 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
print "p -> ", secp256_dparameters[2] == 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
print "gx -> ", secp256_dparameters[3] == 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
print "gy -> ", secp256_dparameters[4] == 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
print "n -> ", secp256_dparameters[5] == 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
print "h -> ", secp256_dparameters[6] == 1



test_curve = EllipticCurve(secp256_dparameters[0], secp256_dparameters[1], secp256_dparameters[2],
                           secp256_dparameters[3], secp256_dparameters[4], secp256_dparameters[5],
                           secp256_dparameters[6])
sk = 0x70a12c2db16845ed56ff68cfc21a472b3f04d7d6851bf6349f2d7d5b3452b38a
pk = test_curve.multiply(sk, test_curve.getGPoint())
print "pk x -> ", hex(pk.x)
print "pk y -> ", hex(pk.y)

if pk.x == 0x8101ece47464a6ead70cf69a6e2bd3d88691a3262d22cba4f7635eaff26680a8 and \
                pk.y == 0xd8a12ba61d599235f67d9cb4d58f1783d3ca43e78f0a5abaa624079936c0c3a9:
    print "PK TEST SUCCESSFUL"
else:
    print "PK TEST FAIL"

k = 0x580ec00d856434334cef3f71ecaed4965b12ae37fa47055b1965c7b134ee45d0
inv_k = euclideans_algorithm.eea(k, secp256_dparameters[5])
if inv_k == 0x6a664fa115356d33f16331b54c4e7ce967965386c7dcbf2904604d0c132b4a74:
    print "TEST INVERSE SUCCESSFUL"
else:
    print "TEST INVERSE FAIL"

R = test_curve.gen_pkey(k)
xr = 0x7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c
xy = 0x8b81e3e977597110c7cf2633435b2294b72642987defd3d4007e1cfc5df84541

if R.x == xr and R.y == xy:
    print "Ephemeral key gen successful"
else:
    print "Ephemeral key gen fail"

r = xr % secp256_dparameters[5]

if r == 0x7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c:
    print "r computation successful"
else:
    print "r computation fail"

M = "This is only a test message. It is 48 bytes long"
if (binascii.hexlify(
        M)) == "54686973206973206f6e6c7920612074657374206d6573736167652e204974206973203438206279746573206c6f6e67":
    print "Message has correct hex"
else:
    print "message fail"
sha256 = hashlib.sha256()
sha256.update(M)
H = sha256.digest()
if binascii.hexlify(H) == "7c3e883ddc8bd688f96eac5e9324222c8f30f9d6bb59e9c5f020bd39ba2b8377":
    print "hash has correct hex"
else:
    print "hash fail"

e = int(H.encode('hex'), 16)
if e == 56197278047627432394583341962843287937266210957576322469816113796290471232375:
    print "HASH ENCONDING CORRECT"
else:
    print int(H.encode('hex'), 16)
    print "HASH ENCONDING FAIL"

s = inv_k * (e + (sk * r)) % secp256_dparameters[5]

print "Testing s value ="
print s == 0x7d1ff961980f961bdaa3233b6209f4013317d3e3f9e1493592dbeaa1af2bc367

print "Signature = (", r, ", ", s, ")"

print "### VALIDATING SIGNATURE ###"
if r > 1 and r < secp256_dparameters[5] - 1 and s > 1 and s < secp256_dparameters[5]:

    sha256 = hashlib.sha256()
    sha256.update(M)
    H_dash = sha256.digest()

    if binascii.hexlify(H) == binascii.hexlify(H_dash):
        print "hash is correct"
    else:
        print "Signature is invalid"

    e_dash = int(H_dash.encode('hex'), 16)
    w = euclideans_algorithm.eea(s, secp256_dparameters[5])

    if w == 0xd69be75f67ee5394cabb6c286f3610cf62d722cba9eea70faee770a6b2ed72dc:
        print "W is correct"
    else:
        print "W is incorrect"

    u1 = (e_dash * w) % secp256_dparameters[5]
    if u1 == 0xbb252401d6fb322bb747184cf2ac52bf8d54b95a1515062a2f6141f2e2092ed8:
        print "u1 value is correct"
    else:
        print "u1 value is incorrect"

    u2 = (r * w) % secp256_dparameters[5]

    if u2 == 0xaae7d1c7f2c232dfc641948af3dba141d4de8634e571cf84c486301b510cfc04:
        print "u2 value is correct"
    else:
        print "u2 value is incorect"

    first = test_curve.multiply(u1, test_curve.getGPoint())
    second = test_curve.multiply(u2, pk)
    R_dash = test_curve.point_addition(first, second)

    if R_dash.x == 0x7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c and R_dash.y == 0x8b81e3e977597110c7cf2633435b2294b72642987defd3d4007e1cfc5df84541:
        print "R value is correct"
    else:
        print "R value is incorect"

    v = R_dash.x % secp256_dparameters[5]

    if v == 0x7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c:
        print "V value is correct"
    else:
        print "V value is incorrect"

    if v == r:
        print "Signature is valid"
    else:
        print "Signature is invalid!"



else:
    print "Signature verification failed" """"""
