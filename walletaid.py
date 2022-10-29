import os.path, binascii, collections, getpass, argparse, hashlib, struct, aes

# Get command-line arguments
parser = argparse.ArgumentParser("walletaid.py",
                                 usage="walletaid.py \"filepath\" pubkeyprefix privkeyprefix [-a address] [-c] [-h]")
parser.add_argument("filepath", help="Path to wallet file (use \"\")")
parser.add_argument("pubkeyprefix", help="public key prefix in hex (e.g. 00 for bitcoin)")
parser.add_argument("privkeyprefix", help="private key prefix in hex (e.g. 80 for bitcoin)")
parser.add_argument("-a", metavar="address", help="address to search the key for")
parser.add_argument("-c", action="store_true", help="check if found private key really matches public key (much slower)")

try:
    args = parser.parse_args()
except:
    print("\n\n")
    parser.print_help()
    exit()

wallet_filename = os.path.abspath(args.filepath)
pubprefix = binascii.unhexlify(args.pubkeyprefix)
privprefix = binascii.unhexlify(args.privkeyprefix)
find_addr = args.a
check_keys = args.c

# Calculates public key from a private key
class Point(object):
    def __init__(self, _x, _y, _order=None): self.x, self.y, self.order = _x, _y, _order

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
            if e & 1: result += q
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


p, INFINITY = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F, Point(None, None)  # secp256k1
g = Point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
          0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
          0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
# End of code used to calculate public key


# AES decryption functions
def decryptkey(privkey, mk, pubkey):
    aescbc = aes.AESModeOfOperationCBC(mk, Hash(pubkey)[:16])
    klist = [privkey[i:i + 16] for i in range(0, len(privkey), 16)]
    kplain = b""
    for k in klist:
        kplain += aescbc.decrypt(k)

    return kplain


def decryptmkey(chmk, vKeyData, vSalt, nIters):
    data = str.encode(vKeyData, encoding="utf-8") + vSalt
    for i in range(nIters):
        data = hashlib.sha512(data).digest()
    key = data[0:32]
    iv = data[32:32 + 16]
    aescbc = aes.AESModeOfOperationCBC(key, iv)

    mklist = [chmk[i:i + 16] for i in range(0, len(chmk), 16)]
    mkplain = b""
    for mk in mklist:
        mkplain += aescbc.decrypt(mk)

    return mkplain


# Base58 encoder
alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58encode(v):
    '''Encode a string using Base58'''

    nPad = len(v)
    v = v.lstrip(b'\0')
    nPad -= len(v)

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    result = b""
    while acc:
        acc, idx = divmod(acc, 58)
        result = alphabet[idx:idx+1] + result

    return (alphabet[0:1] * nPad + result).decode("utf-8")


# SHA-256 hashception function
def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def pubtoaddr(data):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(data).digest())
    md160 = md.digest()
    h = Hash(pubprefix+md160)
    addr = md160 + h[0:4]
    return b58encode(pubprefix+addr)


def privtopub(privkey, compressed):
    c = int(binascii.hexlify(privkey), base=16)
    pubkey = str(g * c)
    pubkey = ("0" * (64 - pubkey.index(" "))) + pubkey
    if compressed:
        if int(pubkey[-1], base=16) % 2 == 0:
            pref = "02"
        else:
            pref = "03"
        pubkey = pubkey[0:64]
    else:
        pref = "04"
        if len(pubkey) < 129:
            zeroadd = "0" * (129-len(pubkey))
            pubkey = pubkey[:64] + zeroadd + pubkey[64:]
        pubkey = pubkey.replace(" ", "")
    return binascii.unhexlify(pref + pubkey)


def privtowif(privkey, compressed):
    privkey = privprefix + privkey
    if compressed:
        privkey = privkey + b"\x01"
    h = Hash(privkey)
    privkey = privkey + h[0:4]
    return b58encode(privkey)


def keycheck(pubkey, privkey, compressed):
    check = False
    if pubkey == privtopub(privkey, compressed):
        check = True
    return check


# Loads wallet.dat
with open(wallet_filename, "rb") as wallet:
    wallet_data = wallet.read()

    mkey_kindex = wallet_data.find(b"\x04mkey\x01\x00\x00\x00", 0)
    mkey_vindex = wallet_data.rfind(b"\x00\x01\x30", 0, mkey_kindex)
    mkey = wallet_data[mkey_vindex + 2:mkey_vindex + 69]
    masterkey = None

    if mkey_kindex != -1:
        password = getpass.getpass("Wallet is encrypted, please enter password\nPassword:")
        encrypted_mkey, salt, method, iterations = struct.unpack_from("< 49p 9p I I", mkey)
        masterkey = decryptmkey(encrypted_mkey, password, salt, iterations)

        if masterkey[-16:] != b"\x10" * 16:
            raise Exception("Wrong password")
        print("Correct password!")
        masterkey = masterkey[:-16]

        kheader = b"\x04\x63\x6B\x65\x79"
        vheader = b"\x00\x01\x30"
        offsets = [6, 71, 3, 51]
    else:
        kheader = b"\x03\x6b\x65\x79"
        vheader = b"\x02\x01\x01\x04\x20"
        offsets = [5, 70, 5, 37]

    keylist = collections.OrderedDict()
    kindex = wallet_data.find(kheader, 0)
    vindex = wallet_data.rfind(vheader, 0, kindex)

    pub = wallet_data[kindex + offsets[0]: kindex + offsets[1]]
    priv = wallet_data[vindex + offsets[2]: vindex + offsets[3]]
    while True:
        if pub[0] != b"\x04":
            pub = pub[:33]
        if pub not in keylist and kindex != -1:
            keylist[pub] = priv

        kindex = wallet_data.find(kheader, kindex + 6)
        vindex = wallet_data.rfind(vheader, 0, kindex)

        if kindex >= 0:
            pub = wallet_data[kindex + offsets[0]: kindex + offsets[1]]
            priv = wallet_data[vindex + offsets[2]: vindex + offsets[3]]
        else:
            break


with open("DUMP.txt", "w") as dump:
    klist_len = len(keylist)
    iters = 0

    for pub_key, priv_key in keylist.items():
        iters += 1
        procinfo = "Processing {}/{} keys".format(iters, klist_len)
        print(procinfo, end="\r")

        comp = True
        if pub_key[0] == b"\x04":
            comp = False

        address = pubtoaddr(pub_key)
        if find_addr:
            if address == find_addr:
                if masterkey:
                    priv_key = decryptkey(priv_key, masterkey, pub_key)[:-16]

                if check_keys and not keycheck(pub_key, priv_key, comp):
                    print("Address found, but private key does not match")
                    break

                wif = privtowif(priv_key, comp)

                print(" " * len(procinfo))
                print("Found private key for {}\nWIF: {}\n\nSaved to DUMP.txt".format(address, wif))
                dump.write("Address: {}\nWIF: {}\n\n".format(address, wif))
                break
            elif iters >= klist_len:
                print("Address not found in wallet")
        else:
            if masterkey:
                priv_key = decryptkey(priv_key, masterkey, pub_key)[:-16]

            if check_keys and not keycheck(pub_key, priv_key, comp):
                wif = "doesn't match address"
            else:
                wif = privtowif(priv_key, comp)

            dump.write("Address: {}\nWIF: {}\n\n".format(address, wif))
            if iters >= klist_len:
                print(" " * len(procinfo))
                print("{} private keys found\n\nsaved to DUMP.txt".format(klist_len))
