import hashlib
import binascii
from ConfigParser import SafeConfigParser

config = SafeConfigParser()
config.read("config.ini")
pubprefix = config.get("settings", "pubkeyprefix")
privprefix = config.get("settings", "privkeyprefix")
compressed = config.getboolean("settings", "compressed")
if not compressed:
    suff = ""
else:
    suff = "01"


class Point(object):
    def __init__(self, _x, _y, _order = None): self.x, self.y, self.order = _x, _y, _order

    def calc(self, top, bottom, other_x):
        l = (top * inverse_mod(bottom)) % p
        x3 = (l * l - self.x - other_x) % p
        return Point(x3, (l * (self.x - x3) - self.y) % p)

    def double(self):
        if self == INFINITY: return INFINITY
        return self.calc(3 * self.x * self.x, 2 * self.y, self.x)

    def __add__(self, other):
        if other == INFINITY: return self
        if self == INFINITY: return other
        if self.x == other.x:
            if (self.y + other.y) % p == 0: return INFINITY
            return self.double()
        return self.calc(other.y - self.y, other.x - self.x, other.x)

    def __mul__(self, e):
        if self.order: e %= self.order
        if e == 0 or self == INFINITY: return INFINITY
        result, q = INFINITY, self
        while e:
            if e&1: result += q
            e, q = e >> 1, q.double()
        return result

    def __str__(self):
        if self == INFINITY: return "infinity"
        return "%x %x" % (self.x, self.y)

def inverse_mod(a):
    if a < 0 or a >= p: a = a % p
    c, d, uc, vc, ud, vd = a, p, 1, 0, 0, 1
    while c:
        q, c, d = divmod(d, c) + (c,)
        uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc
    if ud > 0: return ud
    return ud + p

p, INFINITY = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL, Point(None, None) # secp256k1
g = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L)

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58.
    """

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
def hashtoaddr(a):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(binascii.unhexlify(a)).digest())
    md160 = md.digest()
    h = Hash(binascii.unhexlify(pubprefix)+md160)
    addr = md160 + h[0:4]
    return b58encode(binascii.unhexlify(pubprefix)+addr)

def hashtowif(b):
    presha = binascii.unhexlify(privprefix) + b + binascii.unhexlify(suff)
    h = Hash(presha)
    key = presha + h[0:4]
    return b58encode(key)

def address(c)
    pubkey = str(g * c)
    if pubkey[63] == " ":
        pubkey = "0" + pubkey
    if compressed:
        if int(pubkey[-1], base=16) % 2 == 0:
            pref = "02"
        else:
            pref = "03"
        pubkey = pubkey[0:64]
    else:
        pref = "04"
        if len(pubkey) < 129:
            pubkey = pubkey[:64] + "0" + pubkey[64:]
        pubkey = pubkey.replace(" ", "")
    return hashtoaddr(pref + pubkey)

header = binascii.unhexlify("f70001d63081d30201010420")
keyl = 32
slist = open("foundkeys.txt","w")
klist = []
count = 0
print "Starting search"

with open('wallet.dat', 'rb') as f:
    data = f.read()
    header_index = data.find(header, 0)
    if header_index >= 0:
        body = data[header_index + len(header): header_index + len(header) + keyl]
        privkey = int(binascii.hexlify(body), base = 16)
        pubkey = str(g * privkey)
        while body is not None:
            print "\rScanned {:0.2f} %  ".format(float(header_index) / len(data) * 100),
            if privkey not in klist:
                count += 1
                slist.write("Address: {}\nPrivate key: {}\n\n".format(address(privkey), hashtowif(body)))
                klist.append(privkey)
                
            header_index = data.find(header,\
                                    header_index + len(header) + keyl)
            if header_index >= 0:
                body = data[header_index + len(header): header_index + len(header) + keyl]
                privkey = int(binascii.hexlify(body), base = 16)
            else:
                body = None
print "\rScanned 100 %  "
print "Found %i keys in wallet, check 'foundkeys.txt'" % (count)
