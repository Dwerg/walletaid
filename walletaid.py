"""
Walletaid created by Dwerg using Python 2.7

Code for converting to addresses and WIF
is borrowed from pywallet.
"""

import os.path, bsddb.db, struct, binascii, collections, hashlib
from ConfigParser import SafeConfigParser
from Tkinter import *
import ttk
from aes import *

#Opens config.ini and gets settings, checks if wallet.dat is in folder
config = SafeConfigParser()

if not os.path.exists("config.ini"):
    print "The config.ini file was not found"
    exit(0)
if not os.path.exists("wallet.dat"):
    print "The wallet.dat file is not in folder or has different name"
    exit(0)

config.read("config.ini")
pubprefix = config.get("settings", "pubkeyprefix")
privprefix = config.get("settings", "privkeyprefix")
compressed = config.getboolean("settings", "compressed")
wallet_filename = os.path.abspath("wallet.dat")

#Loads wallet.dat
with open(wallet_filename, "rb") as wallet_file:
    wallet_file.seek(12)
    if wallet_file.read(8) != b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
        print("ERROR: file is not a wallet or header is corrupted!")
        sys.exit(1)

    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_PRIVATE | bsddb.db.DB_THREAD | bsddb.db.DB_INIT_LOCK | bsddb.db.DB_INIT_MPOOL | bsddb.db.DB_CREATE)
    db = bsddb.db.DB(db_env)

    db.open(wallet_filename, b"main", bsddb.db.DB_BTREE, bsddb.db.DB_THREAD | bsddb.db.DB_RDONLY)
    mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
    words = ""
    recov_pass = ""
    if mkey:
        klist = collections.OrderedDict()
        for k in db.keys():
            if binascii.hexlify(k)[0:10] == "04636b6579":
                klist[k] = db[k]
        bip39words = db.get(b"\x0bcbip39words")
        recov_pass = db.get(b"\x10cbip39passphrase")
        if bip39words:
            words = bip39words[33:]
            wordhash = bip39words[:32]
        if recov_pass:
            recov_pass = recov_pass[1:]
    else:
        words = db.get(b"\x0abip39words")
        recov_pass = db.get(b"\x0fbip39passphrase")
        if words:
            words = words[33:]
        if recov_pass:
            recov_pass = recov_pass[1:]
        klist = []
        header = binascii.unhexlify("0201010420")
        data = wallet_file.read()
        header_index = data.find(header, 0)
        key = data[header_index + len(header): header_index + len(header) + 32]
        while True:
            if key not in klist:
                klist.append(key)

            header_index = data.find(header,header_index + len(header) + 32)
            if header_index >= 0:
                key = data[header_index + len(header): header_index + len(header) + 32]
            else:
                break

#Used to decrypt masterkey and encrypted private keys
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

#Calculates public key from a private key
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
#End of code used to calculate public key

#Base58 encoder
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

    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

#SHA-256 hashception function
def Hash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

#Takes hexadecimal public key, spits out address
def hashtoaddr(a):
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(binascii.unhexlify(a)).digest())
    md160 = md.digest()
    h = Hash(binascii.unhexlify(pubprefix)+md160)
    addr = md160 + h[0:4]
    return b58encode(binascii.unhexlify(pubprefix)+addr)

#Takes hexadecimal private key, spits out WIF
def hashtowif(b):
    presha = binascii.unhexlify(privprefix) + b
    if compressed: presha = presha + binascii.unhexlify("01")
    h = Hash(presha)
    key = presha + h[0:4]
    return b58encode(key)

#Takes hexadecimal private key, spits out address
def address(c):
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
            pubkey = pubkey[:64] + "0" + pubkey[64:]
        pubkey = pubkey.replace(" ", "")
    return hashtoaddr(pref + pubkey)

#GUI and code for printing output to textbox and file.
print "Opening GUI"

def pw_entered(event=None):
    pwbox_frame.destroy()
    frame1.grid()

#Gets and decrypts mnemonic
def getSeed():
    wallet_pass_phrase = entered_pass.get()
    frame1.destroy()
    proBar.destroy()
    frame3.grid()

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

        try:
            result = strip_PKCS7_padding(dec_data)
        except:
            result = dec_data
        return result

    seedwords = "No BIP39 words found"

    if mkey and wallet_pass_phrase and words:
        crypter = Crypter()
        encrypted_mkey, salt, method, iterations = struct.unpack_from("< 49p 9p I I", mkey)
        crypter.SetKeyFromPassphrase(wallet_pass_phrase, salt, iterations, method)
        masterkey = crypter.Decrypt(encrypted_mkey)
        crypter.SetKey(masterkey)
        crypter.SetIV(wordhash)
        uc_words = decrypt_words(words)

        if wordhash == Hash(uc_words):
            if recov_pass:
                seedwords = "Mnemonic words:\n" + uc_words + "\n\nRecovery passphrase:\n" + decrypt_words(recov_pass)
            else:
                seedwords = "Mnemonic words:\n" + uc_words
        else:
            seedwords = "Wrong password!"
    elif words:
        if recov_pass:
            seedwords = "Mnemonic words:\n" + words + "\n\nRecovery passphrase:\n" + recov_pass
        else:
            seedwords = "Mnemonic words:\n" + words

    if seedwords[0:8] == "Mnemonic":
        keyfile = open("DUMP.txt", "w")
        keyfile.write(seedwords)
        outBox.configure(state='normal')
        outBox.insert("end", seedwords + "\n\nFound mnemonic, saved to DUMP.txt")
        outBox.configure(state='disabled')
    else:
        outBox.configure(state='normal')
        outBox.insert("end", seedwords)
        outBox.configure(state='disabled')

#Prints all keys.
def getAll():
    wallet_pass_phrase = entered_pass.get()
    frame1.destroy()
    frame3.grid()
    keyfile = open("DUMP.txt","w")
    count = 0
    if mkey and wallet_pass_phrase:
        data = klist
        try:
            os.remove("__db.001")
            os.remove("__db.002")
            os.remove("__db.003")
        except:
            pass
        proBar["maximum"] = len(data)

        crypter = Crypter()
        encrypted_mkey, salt, method, iterations = struct.unpack_from("< 49p 9p I I", mkey)
        crypter.SetKeyFromPassphrase(wallet_pass_phrase, salt, iterations, method)
        masterkey = crypter.Decrypt(encrypted_mkey)
        crypter.SetKey(masterkey)

        for key, value in data.items():
            count += 1
            if binascii.hexlify(key)[0:10] == "04636b6579":
                pub_key = key[6:39]
                enc_priv_key = value[1:49]
                crypter.SetIV(Hash((pub_key)))
                dec_key = crypter.Decrypt(enc_priv_key)

                addr = address(int(binascii.hexlify(dec_key), base = 16))
                if(hashtoaddr(binascii.hexlify(pub_key))) == addr:
                    privkey = hashtowif(dec_key)
                else:
                    privkey = "Wrong password"
                keyfile.write("Address: {}\nPrivate key: {}\n\n".format(addr, privkey))

                outBox.configure(state='normal')
                outBox.insert('end', "Address: {}\nPrivate key: {}\n\n".format(addr, privkey))
                outBox.configure(state='disabled')
                outBox.yview_moveto(1.0)
            outBox.update()
            proBar["value"] = count


    else:
        proBar["maximum"] = len(klist)

        for k in klist:
            count += 1
            addr = address(int(binascii.hexlify(k), base = 16))
            privkey = hashtowif(k)
            keyfile.write("Address: {}\nPrivate key: {}\n\n".format(addr, privkey))

            outBox.configure(state='normal')
            outBox.insert('end', "Address: {}\nPrivate key: {}\n\n".format(addr, privkey))
            outBox.configure(state='disabled')
            outBox.yview_moveto(1.0)
            outBox.update()
            proBar["value"] = count

    outBox.configure(state='normal')
    outBox.insert("end", "Finished search!\nSaved found keypairs to 'foundkeys.txt'")
    outBox.configure(state='disabled')
    outBox.yview_moveto(1.0)

#Goes to search window.
def searchWin():
    frame1.destroy()
    frame2.grid()

#Finds keys for addresses inputted by user, prints if found.
def submitSearch():
    searchList = inField.get("1.0", END).split()
    wallet_pass_phrase = entered_pass.get()
    frame2.destroy()
    frame3.grid()
    keyfile = open("DUMP.txt","w")
    found = False
    count = 0
    if mkey and wallet_pass_phrase:
        data = klist
        proBar["maximum"] = len(data)

        crypter = Crypter()
        encrypted_mkey, salt, method, iterations = struct.unpack_from("< 49p 9p I I", mkey)
        crypter.SetKeyFromPassphrase(wallet_pass_phrase, salt, iterations, method)
        masterkey = crypter.Decrypt(encrypted_mkey)
        crypter.SetKey(masterkey)

        for key, value in data.items():
            count += 1
            pub_key = binascii.hexlify(key)[12:78]
            enc_priv_key = binascii.hexlify(value)[2:98]
            if binascii.hexlify(key)[0:10] == "04636b6579":
                crypter.SetIV(Hash((binascii.unhexlify(pub_key))))

                for keysearch in searchList:
                    if keysearch == hashtoaddr(pub_key):
                        dec_key = crypter.Decrypt(binascii.unhexlify(enc_priv_key))
                        addr = address(int(binascii.hexlify(dec_key), base=16))
                        if (hashtoaddr(pub_key)) == addr:
                            privkey = hashtowif(dec_key)
                        else:
                            privkey = "Wrong password"
                        keyfile.write("Address: {}\nPrivate key: {}\n\n".format(addr, privkey))
                        found = True

                        outBox.configure(state='normal')
                        outBox.insert('end', "Address: {}\nPrivate key: {}\n\n".format(addr, privkey))
                        outBox.configure(state='disabled')
                        outBox.yview_moveto(1.0)
            outBox.update()
            proBar["value"] = count


    else:
        proBar["maximum"] = len(klist)

        for k in klist:
            count += 1
            addr = address(int(binascii.hexlify(k), base = 16))
            for keysearch in searchList:
                if addr == keysearch:
                    privkey = hashtowif(k)
                    keyfile.write("Address: {}\nPrivate key: {}\n\n".format(addr, privkey))
                    found = True

                    outBox.configure(state='normal')
                    outBox.insert('end', "Address: {}\nPrivate key: {}\n\n".format(addr, privkey))
                    outBox.configure(state='disabled')
                    outBox.yview_moveto(1.0)
            outBox.update()
            proBar["value"] = count

    if not found:
        outBox.configure(state='normal')
        outBox.insert("end", "Entered address(es) was not found!")
        outBox.configure(state='disabled')
    else:
        outBox.configure(state='normal')
        outBox.insert("end", "Finished search!\nSaved found keypairs to 'foundkeys.txt'")
        outBox.configure(state='disabled')
        outBox.yview_moveto(1.0)

#Quits the program.
def kill():
    try:
        os.remove("__db.001")
        os.remove("__db.002")
        os.remove("__db.003")
    except:
        pass
    root.destroy()

#Sets up the GUI frames.
root = Tk()
root.title("Walletaid")
root.resizable(width=False, height=False)

#Functions frame
frame1 = Frame(root)

instruction=Label(frame1,
    text="Choose an option!",
    font=("", 11, "bold")
    )
instruction.grid(row=0, column=1, columnspan=2)

selButton1 = Button(frame1, text="Get all keys", command=getAll)
selButton2 = Button(frame1, text="Search for specific keys", command=searchWin)
selButton3 = Button(frame1, text="Get seed words", command=getSeed)
selButton1.grid(row=1, column=1)
selButton2.grid(row=1, column=2)
selButton3.grid(row=3, column=1, columnspan=2)

spacing1 = Frame(frame1, height=10)
spacing2 = Frame(frame1, width=10)
spacing3 = Frame(frame1, width=10)
spacing1.grid(row=2, columnspan=2)
spacing2.grid(column=0, rowspan=3)
spacing3.grid(column=3, rowspan=2)
#End startup frame

#Search frame
frame2 = Frame(root)

instruction=Label(frame2,
    text="Enter a list of addresses to search for below",
    font=("", 11 , "bold")
    )
instruction.grid(row=0, column=1)

inField = Text(frame2, height=15, width=40)
inField.grid(row=1, column=1)

okButton = Button(frame2, text="OK", command=submitSearch)
okButton.grid(row=2, column=1, padx=55, pady=5, sticky=E)

cancelButton = Button(frame2, text="Close", command=kill)
cancelButton.grid(row=2, column=1, padx=5, pady=5, sticky=E)

spacing4 = Frame(frame2, width=10)
spacing5 = Frame(frame2, width=10)
spacing4.grid(column=0, rowspan=2)
spacing5.grid(column=2, rowspan=2)
#End search frame

#Output frame
frame3 = Frame(root)

proBar = ttk.Progressbar(frame3, orient=HORIZONTAL, length=300, mode="determinate",)
proBar.grid(column=1)

scrollbar = Scrollbar(frame3)
outBox = Text(frame3, height=20, width=70, state="disabled", yscrollcommand=scrollbar.set)

outBox.grid(row=1, column=1)
scrollbar.grid(row=1, column=2, sticky=N+S)
scrollbar.config(command=outBox.yview)

closeButton = Button(frame3, height=2, width=15, text="Close", font=("", 11 , "bold"), command=kill)
closeButton.grid(row=2, column=1, pady=10)

spacing6 = Frame(frame3, width=10)
spacing7 = Frame(frame3, width=10)
spacing6.grid(column=0, rowspan=2)
spacing7.grid(column=3, rowspan=2)
#End output frame

#Password entry frame
pwbox_frame = Frame(root)

instruction=Label(pwbox_frame,
    text="Enter password",
    font=("", 11 , "bold")
    )
instruction.grid(row=0, column=1, columnspan=2)

entered_pass = StringVar()
pwField = Entry(pwbox_frame, textvariable=entered_pass, show="*", width=40)
pwField.grid(row=1, column=1)

pwButton = Button(pwbox_frame, text="OK", command=pw_entered)
pwButton.grid(row=2, column=1)
#End password entry frame

#Launches the GUI
if(mkey):
    pwbox_frame.grid()
    pwField.focus()
    pwField.bind("<Return>", pw_entered)
else:
    frame1.grid()
root.mainloop()
