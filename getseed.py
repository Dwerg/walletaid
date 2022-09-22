import sys, os.path, bsddb.db, struct, hashlib
from aes import *

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
                wordsfile = open("SEEDWORDS.txt","w")
                wordsfile.write(seedwords)
                print("\nWords saved to SEEDWORDS.txt")
            except:
                print("Wrong password")
        else:
            seedwords = "Mnemonic words:\n" + words + "\n\nRecovery passphrase:\n" + recov_pass
            print(seedwords)
            wordsfile = open("SEEDWORDS.txt","w")
            wordsfile.write(seedwords)
            print("\nWords saved to SEEDWORDS.txt")
    else:
        if is_enc:
            try:
                seedwords = "Mnemonic words:\n" + decrypt_words(words)
                print(seedwords)
                wordsfile = open("SEEDWORDS.txt","w")
                wordsfile.write(seedwords)
                print("\nWords saved to SEEDWORDS.txt")
            except:
                print("Wrong password")
        else:
            seedwords = "Mnemonic words:\n" + words
            print(seedwords)
            wordsfile = open("SEEDWORDS.txt","w")
            wordsfile.write(seedwords)
            print("\nWords saved to SEEDWORDS.txt")
else:
    print("No BIP39 words found")
