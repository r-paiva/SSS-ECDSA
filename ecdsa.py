import sys
from random import SystemRandom
from modular_inverse import euclideans_algorithm
import hashlib
import base64
from datetime import datetime


class Point(object):
    def __init__(self, x, y):
        self.x = x
        self.y = y


class EllipticCurve(object):
    def __init__(self, a, b, p, gx, gy, n, h):
        self.a = a
        self.b = b
        self.p = p
        self.Gx = gx
        self.Gy = gy
        self.n = n
        self.h = h
        self.Ox = self.Gx
        self.Oy = (self.p - self.Gy) % self.p

    def getInfPoint(self):
        return Point(self.Ox, self.Oy)

    def getGPoint(self):
        return Point(self.Gx, self.Gy)

    def testPoint(self, c_point):
        return (c_point.y * c_point.y) % self.p == (c_point.x * c_point.x * c_point.x + self.a * c_point.x + self.b) % self.p

    def __point_doubling(self, point1):

        s = ((3 * (point1.x * point1.x) + self.a) * (euclideans_algorithm.eea(2 * point1.y, self.p)) % self.p)
        x3 = (s * s - point1.x - point1.x) % self.p
        y3 = (s * (point1.x - x3) - point1.y) % self.p
        result_point = Point(x3, y3)

        if self.testPoint(result_point):
            return result_point
        else:
            print "Result Point: x = %d, y = %d" % (result_point.x, result_point.y)
            raise Exception("Point doubling does not result in a valid curve point. Aborting.")

    def point_addition(self, point1, point2):
            # If we try to add the same point
            if point1.x == point2.x and point1.y == point2.y:
                return self.__point_doubling(point1)
            # if we are adding different points
            else:

                if point1.x == point2.x and point1.y == (self.p - point2.y) % self.p:
                    return Point(0, 0)

                if point1.x == 0 and point1.y == 0:
                    return Point(point2.x, point2.y)

                if point2.x == 0 and point2.y == 0:
                    return Point(point1.x, point1.y)

                neg_flag = 1
                if point2.x - point1.x < 0:
                    neg_flag = -1
                    inv = euclideans_algorithm.eea(abs(point2.x - point1.x), self.p)
                else:
                    inv = euclideans_algorithm.eea(point2.x - point1.x, self.p)

                s = ((point2.y - point1.y) * (inv*neg_flag)) % self.p
                x3 = (s*s - point1.x - point2.x) % self.p
                y3 = (s * (point1.x - x3) - point1.y) % self.p
                result_point = Point(x3, y3)
                if self.testPoint(result_point):
                    return result_point
                else:
                    raise Exception("Point addition does not result in a valid curve point. Aborting.")

    def multiply(self, d, A):
        N = A
        R = Point(0, 0)
        for bit in range(0, d.bit_length()):
            if d & (1 << bit):
                R = self.point_addition(R, N)
            N = self.point_addition(N, N)

        return R

    def gen_skey(self):
        system = SystemRandom()
        return system.randrange(self.n) + 1

    def gen_pkey(self, d):
        return self.multiply(d, self.getGPoint())

    def sign(self, data, skey, hash_value):
        system = SystemRandom()
        ephemeral = system.randrange(self.n) + 1
        R = self.multiply(ephemeral, self.getGPoint())
        r = R.x % self.n
        inv_ephemeral = euclideans_algorithm.eea(ephemeral, self.n)
        if hash_value == "sha256":
            sha256 = hashlib.sha256()
            sha256.update(data)
            H = sha256.digest()
        elif hash_value == "sha384":
            sha384 = hashlib.sha384()
            sha384.update(data)
            H = sha384.digest()
        else:
            sha512 = hashlib.sha512()
            sha512.update(data)
            H = sha512.digest()

        e = int(H.encode('hex'), 16)
        return r, (inv_ephemeral * (e + (skey * r))) % self.n

    def verify_sig(self, r, s, pk, M, hash_value):
        if 1 < r < self.n -1 and 1 < s < self.n -1:
            #calculate hash of message
            if hash_value == "sha256":
                sha256 = hashlib.sha256()
                sha256.update(M)
                H = sha256.digest()
            elif hash_value == "sha384":
                sha384 = hashlib.sha384()
                sha384.update(M)
                H = sha384.digest()
            else:
                sha512 = hashlib.sha512()
                sha512.update(M)
                H = sha512.digest()
            e = int(H.encode('hex'), 16)
            w = euclideans_algorithm.eea(s, self.n)
            u1 = (e * w) % self.n
            u2 = (r * w) % self.n
            R = self.point_addition(self.multiply(u1, self.getGPoint()), self.multiply(u2, pk))
            v = R.x % self.n
            if v == r:
                return "Signature Validates!"
            else:
                return "Signature FAIL!"

    def __str__(self):
        return "Curve Equation: y^2 = (x^3 + %Gx + %G) mod %G" % (self.a, self.b, self.p)


if __name__ == '__main__':

    """
        Domain Parameters:
        a -> curve parameter
        b -> curve parameter
        p -> modulo value
        gx -> x coordinate of the generator point
        gy -> y coordinate of the generator point
        n -> number of points in the generator group
        h -> cofactor

    """
    available_hash = ["sha256", "sha384", "sha512"]
    available_curves = {}

    brainpoolP160r1_list = [
        0x340E7BE2A280EB74E2BE61BADA745D97E8F7C300, #a
        0x1E589A8595423412134FAA2DBDEC95C8D8675E58, #b
        0xE95E4A5F737059DC60DFC7AD95B3D8139515620F, #p
        0xBED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3, #gx
        0x1667CB477A1A8EC338F94741669C976316DA6321, #gy
        0xE95E4A5F737059DC60DF5991D45029409E60FC09, #n
        1, #h
    ]

    available_curves["brainpoolP160r1"] = brainpoolP160r1_list

    brainpoolP192r1_list = [
        0x6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF, #a
        0x469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9, #b
        0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297, #p
        0xC0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6, #gx
        0x14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F, #gy
        0xC302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1, #n
        1, #h
    ]

    available_curves["brainpoolP192r1"] = brainpoolP192r1_list

    brainpoolP224r1_list = [
        0x68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43, #a
        0x2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B, #b
        0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF, #p
        0xD9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D, #gx
        0x58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD, #gy
        0xD7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F, #n
        1, #h

    ]

    available_curves["brainpoolP224r1"] = brainpoolP224r1_list

    brainpoolP256r1_list = [
        0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9, #a
        0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6, #b
        0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377, #p
        0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262, #gx
        0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997, #gy
        0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7, #n
        1, #h
    ]

    available_curves["brainpoolP256r1"] = brainpoolP256r1_list

    brainpoolP320r1_list = [
        0x3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB, #a
        0x520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6, #b
        0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27, #p
        0x43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611, #gx
        0x14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1, #gy
        0xD35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311, #n
        1, #h
    ]

    available_curves["brainpoolP320r1"] = brainpoolP320r1_list

    brainpoolP384r1_list = [
        0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826, #a
        0x4A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11, #b
        0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53, #p
        0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E, #gx
        0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315, #gy
        0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565, #n
        1, #h
    ]

    available_curves["brainpoolP384r1"] = brainpoolP384r1_list

    brainpoolP512r1_list = [
        0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA, #a
        0x3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723, #b
        0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3, #p
        0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822, #gx
        0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892, #gy
        0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069, #n
        1, #h
    ]

    available_curves["brainpoolP512r1"] = brainpoolP512r1_list

    secp256r1_list = [
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC, #a
        0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B, #b
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF, #p
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, #gx
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, #gy
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551, #n
        1 #h
    ]

    available_curves["secp256r1"] = secp256r1_list

    secp384r1_list = [
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC, #a
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF, #b
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF, #p
        0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7, #gx
        0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f, #gy
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973, #n
        1 #h
    ]

    available_curves["secp384r1"] = secp384r1_list

    secp521r1_list = [
        0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC, #a
        0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00, #b
        0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, #p
        0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, #gx
        0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650, #gy
        0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409, #n
        1 #h
    ]

    available_curves["secp521r1"] = secp521r1_list

    usage = """Usage: python ecdsa [-mode] [-options}
mode:
     --generate-keys, -gen                        Genereate cryptographic key pairs.
            options:
                -c, --curve     [curve_name]       Defines the curve that the keypair will be generated from.
                -o, --output    [output_file]      Defines the output file where the PRIVATE KEY will be stored.
                                                        The public key will be stored in a file with the same name, but with a preceding 'pk_'

     --sign, -s                                   Enter signing mode.
            options:
                -m, --message   [message_file]     Define the message to sign.
    *OPTIONAL*  -h, --hash      [hash_algorithm]   Define the hashing algorithm. This value is optional. SHA256 will be used if none value is specified.
                -i, --input     [private_key]      Define private key file.
                -o, --output    [output_file]      Define the output file, this is where the signature will be written.

    --verify, -v
            options:
                -m, --message   [message_file]     Define the message file which has a signature that needs to be verified.
                -s, --signature [signature_file]  Define the signature file. This file must contain a valid signature.
                -p, --public    [public_key]       Define the file where the public key is stored.

            """
    input_curve = ""

    if len(sys.argv) == 1:
        print usage
        exit(1)
    if sys.argv[1] == "--generate-keys" or sys.argv[1] == "-gen":
        if len(sys.argv) > 2:
            if sys.argv[2] == "-c" or sys.argv[2] == "--curve":
                if len(sys.argv) > 3:
                    input_curve = sys.argv[3]
                    if available_curves.has_key(input_curve):
                        (a, b, p, gx, gy, n, h) = available_curves.get(input_curve)
                        curve = EllipticCurve(a, b, p, gx, gy, n, h)
                        sk = curve.gen_skey()
                        pk = curve.gen_pkey(sk)
                        if len(sys.argv) > 4 and (sys.argv[4] == "-o" or sys.argv[4] == "-outfile"):
                            if len(sys.argv) > 4:
                                file = open(sys.argv[5], "w")
                                file.write(input_curve+"\n")
                                file.write(base64.b64encode(format(sk, 'x')))
                                file.close()
                                pkey_file = open("pub_"+sys.argv[5], "w")
                                pkey_file.write(input_curve+"\n")
                                pkey_file.write(base64.b64encode(format(pk.x, 'x')))
                                pkey_file.write("\n")
                                pkey_file.write(base64.b64encode(format(pk.y, 'x')))
                                pkey_file.close()
                                stop = datetime.now()
                            else:
                                print usage
                                exit(1)

                        else:
                            print "please specify an output file: [-o | --outfile] \"filename\""
                    else:
                        print "defined curve is not valid. Please issue --list-curves for a list of available curves."
                        exit(1)
                else:
                    print "Wrong output format given"
                    print usage
                    exit(1)
            else:
                print usage
        else:
            print "You need to define a curve."
            print usage
            exit(1)
    elif sys.argv[1] == "--sign" or sys.argv[1] == "-s":
        hash_value = "sha256"
        hash_input = 0
        if len(sys.argv) > 2:
            if sys.argv[2] == "-m" or sys.argv[2] == "--message":
                if len(sys.argv) > 3:
                    file_to_sign = open(sys.argv[3], "r")
                    data_to_sign = file_to_sign.read()
                    file_to_sign.close()
                    if len(sys.argv) > 5 and (sys.argv[4] == "-h" or sys.argv[4] == "--hash"):
                        hash_value = sys.argv[5]
                        hash_input = 2
                    if len(sys.argv) > (5+hash_input) and (sys.argv[4+hash_input] == "-i" or sys.argv[4+hash_input] == "--input"):
                        sk_file = open(sys.argv[5+hash_input], "r")
                        curve = sk_file.readline().strip()
                        sk = long(base64.b64decode(sk_file.readline()), 16)
                        if available_curves.has_key(curve):
                            (a, b, p, gx, gy, n, h) = available_curves.get(curve)
                            curve = EllipticCurve(a, b, p, gx, gy, n, h)
                            r, s = curve.sign(data_to_sign, sk, hash_value)
                            if len(sys.argv) > 7+hash_input and (sys.argv[6+hash_input] == "-o" or sys.argv[6+hash_input] == "--output"):
                                write_sig_file = open(sys.argv[7+hash_input], "w")
                                write_sig_file.write(hash_value)
                                write_sig_file.write("\n")
                                write_sig_file.write(base64.b64encode(format(r, 'x')))
                                write_sig_file.write("\n")
                                write_sig_file.write(base64.b64encode(format(s, 'x')))
                                write_sig_file.close()
                                print "Signature: ", r, s

                            else:
                                print "Signature: ", base64.b64encode(r), base64.b64encode(s)

                        else:
                            print "cannot process curve from private key file. Aborting."
                            exit(1)
                    else:
                        print "You need to specify the private key file."
                        print usage
                        exit(1)
                else:
                    print "You need to specify the message file."
                    print usage
                    exit(1)
        else:
            print "You need to specify a message [-m | --message] 'message_file' "
            print usage
            exit(1)

    elif sys.argv[1] == "--verify" or sys.argv[1] == "-v":
        if len(sys.argv) > 3 and (sys.argv[2] == "--message" or sys.argv[2] == "-m"):
            data_file = open(sys.argv[3], "r")
            data = data_file.read()
            if len(sys.argv) > 5 and (sys.argv[4] == "-s" or sys.argv[4] == "--signature"):
                sig_file = open(sys.argv[5], "r")
                hash_value = sig_file.readline()[:-1]
                r_line = sig_file.readline()[:-1]
                s_line = sig_file.readline()
                r = long(base64.b64decode(r_line), 16)
                s = long(base64.b64decode(s_line), 16)
                if len(sys.argv) > 7 and (sys.argv[6] == "-p" or sys.argv[6] == "--public"):
                    pk_file = open(sys.argv[7], "r")
                    input_curve = pk_file.readline().strip()
                    if available_curves.has_key(input_curve):
                        pk_x = pk_file.readline()[:-1]
                        pk_x = long(base64.b64decode(pk_x), 16)
                        pk_y = pk_file.readline()
                        pk_y = long(base64.b64decode(pk_y), 16)
                        (a, b, p, gx, gy, n, h) = available_curves.get(input_curve)
                        curve = EllipticCurve(a, b, p, gx, gy, n, h)
                        print curve.verify_sig(r, s, Point(pk_x, pk_y), data, hash_value)
                    else:
                        print "wrong curve in public key file."
                else:
                    print "You need to define the public key file."
                    print usage
                    exit(1)
            else:
                print "You need to define the signature file."
                print usage
                exit(1)
        else:
            print "You need to define the message file."
            print usage
            exit(1)

    elif sys.argv[1] == "--list-curves" or sys.argv[1] == "-l":
        print "The available elliptic curves are: "
        print available_curves.keys()

