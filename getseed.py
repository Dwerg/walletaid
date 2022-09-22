import sys, os.path, bsddb.db, struct, hashlib
from aes import *
from binascii import hexlify, unhexlify


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


class Crypter(object):
    def __init__(self):
        self.m = AESModeOfOperation()
        self.cbc = self.m.modeOfOperation["CBC"]
        self.sz = self.m.aes.keySize["SIZE_256"]

    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        data = vKeyData + vSalt
        for i in range(nDerivIterations):
            data = hashlib.sha512(data).digest()
        self.SetKey(data[0:32])
        self.SetIV(data[32:32+16])
        return len(data)

    def SetKey(self, key):
        self.chKey = [ord(i) for i in key]

    def SetIV(self, iv):
        self.chIV = [ord(i) for i in iv]

    def Encrypt(self, data):
        mode, size, cypher = self.m.encrypt(data, self.cbc, self.chKey, self.sz, self.chIV)
        return ''.join(map(chr, cypher))
 
    def Decrypt(self, data):
        chData = [ord(i) for i in data]
        return self.m.decrypt(chData, self.sz, self.cbc, self.chKey, self.sz, self.chIV)

wallet_filename = os.path.abspath("wallet.dat")

def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

with open(wallet_filename, "rb") as wallet_file:
        wallet_file.seek(12)
        if wallet_file.read(8) != b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
                print(prog+": ERROR: file is not a wallet or header is corrupted!")
                sys.exit(1)


        db_env = bsddb.db.DBEnv()
        db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_PRIVATE | bsddb.db.DB_THREAD | bsddb.db.DB_INIT_LOCK | bsddb.db.DB_INIT_MPOOL | bsddb.db.DB_CREATE)
        db = bsddb.db.DB(db_env)

        db.open(wallet_filename, b"main", bsddb.db.DB_BTREE, bsddb.db.DB_THREAD | bsddb.db.DB_RDONLY)
        encrypted_master_key = db.get(b"\x04mkey\x01\x00\x00\x00")
        is_enc = False
        recov_pass = ""
        for k in db.keys():
            if "bip39words" in k:
                if k[1:2] is "c":
                    is_enc = True
                    wordhash = db[k][:32]
                words = db[k][33:]
            if "bip39passphrase" in k:
                recov_pass = db[k][1:]

if is_enc:
    wallet_pass_phrase = raw_input("Password: ")
    os.system('cls')
    crypter = Crypter()
    encrypted_mkey, salt, method, iterations = struct.unpack_from("< 49p 9p I I", encrypted_master_key)
    crypter.SetKeyFromPassphrase(wallet_pass_phrase, salt, iterations, method)
    mkey = crypter.Decrypt(encrypted_mkey)
    crypter.SetKey(mkey)
    crypter.SetIV(wordhash)

def decrypt_words(enc_data):
    dec_data = ""
    scan = 0
    while len(enc_data) > scan:
        if scan is 0:
            res = crypter.Decrypt(enc_data[scan:])
        else:
            res = crypter.Decrypt(enc_data[scan:])[16:]
        scan += 16
        dec_data += res
        
    return strip_PKCS7_padding(dec_data)

if words:
    if recov_pass:
        if is_enc:
            try:
                seedwords = "Mnemonic words:\n" + decrypt_words(words) + "\n\nRecovery passphrase:\n" + decrypt_words(recov_pass)
                print(seedwords)
                wordsfile = open("SEED.txt","w")
                wordsfile.write(seedwords)
                print("\nWords saved to SEED.txt")
            except:
                print("Wrong password")
        else:
            seedwords = "Mnemonic words:\n" + words + "\n\nRecovery passphrase:\n" + recov_pass
            print(seedwords)
            wordsfile = open("SEED.txt","w")
            wordsfile.write(seedwords)
            print("\nWords saved to SEED.txt")
    else:
        if is_enc:
            try:
                seedwords = "Mnemonic words:\n" + decrypt_words(words)
                print(seedwords)
                wordsfile = open("SEED.txt","w")
                wordsfile.write(seedwords)
                print("\nWords saved to SEED.txt")
            except:
                print("Wrong password")
        else:
            seedwords = "Mnemonic words:\n" + words
            print(seedwords)
            wordsfile = open("SEED.txt","w")
            wordsfile.write(seedwords)
            print("\nWords saved to SEED.txt")
else:
    print("No BIP39 words found")
