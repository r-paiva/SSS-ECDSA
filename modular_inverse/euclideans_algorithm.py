def egcd(value, mod):
    if value == 0:
        return mod, 0, 1
    else:
        g, x, y = egcd(mod % value, value)
        return g, y - (mod // value) * x, x


def mulinv(value, mod):
    g, x, _ = egcd(value, mod)
    if g == 1:
        return x % mod


# returns the inverse of a value mod 'mod'
# example: eea(7,40) returns the inverse of : 7 mod 40; which is 23.
def eea(value, mod):
    return mulinv(value, mod)