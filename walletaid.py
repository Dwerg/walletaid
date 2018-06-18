"""
Walletaid created by Dwerg using Python 2.7

Code for converting to addresses and WIF
is borrowed from pywallet.
"""

import hashlib
import binascii
from os import path
from ConfigParser import SafeConfigParser
from Tkinter import *
import ttk

#Opens config.ini and gets settings, checks if wallet.dat is in folder
config = SafeConfigParser()

if not path.exists("config.ini"):
    print "The config.ini file was not found"
    exit(0)
if not path.exists("wallet.dat"):
    print "The wallet.dat file is not in folder or has different name"
    exit(0)

config.read("config.ini")
pubprefix = config.get("settings", "pubkeyprefix")
privprefix = config.get("settings", "privkeyprefix")
compressed = config.getboolean("settings", "compressed")

#Loads wallet.dat into lists of addresses and private keys
with open('wallet.dat', 'rb') as f:
    count = 0
    klist = []
    header = binascii.unhexlify("0201010420")
    data = f.read()
    header_index = data.find(header, 0)
    key = data[header_index + len(header): header_index + len(header) + 32]
    while True:
        if key not in klist:
            count += 1
            #print "\rLoading wallet.dat {:.0f} %  ".format(float(header_index) / len(data) * 100),
            klist.append(key)
            
        header_index = data.find(header,header_index + len(header) + 32)
        if header_index >= 0:
            key = data[header_index + len(header): header_index + len(header) + 32]
        else:
            break
print "\rLoading wallet.dat 100 %  \nLoaded {} keys from wallet.dat\n".format(count)
maxcount = len(klist)

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

#Prints all keys.
def getAll():
    frame1.destroy()
    frame3.grid()
    keyfile = open("foundkeys.txt","w")
    count = 0
    for k in klist:
        count += 1
        addr = address(int(binascii.hexlify(k), base = 16))
        privkey = hashtowif(k)
        keyfile.write("Address: {}\nPrivate key: {}\n\n".format(addr, privkey))

        #keyCount.set("Hashing key {}/{}".format(count, maxcount))
        
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
    frame2.destroy()
    frame3.grid()
    keyfile = open("foundkeys.txt","w")
    found = False
    count = 0
    for k in klist:
        count += 1
        addr = address(int(binascii.hexlify(k), base = 16))
        #keyCount.set("Checking key {}/{}".format(count, maxcount))
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
    root.destroy()

#Sets up the GUI frames.
root = Tk()
root.title("Walletaid")
root.resizable(width=False, height=False)

#Startup frame
frame1 = Frame(root)
frame1.grid()

instruction=Label(frame1,
    text="Choose an option!",
    font=("", 11 , "bold")
    )
instruction.grid(row=0, column=1, columnspan=2)

selButton1 = Button(frame1, text="Get all keys", command=getAll)
selButton2 = Button(frame1, text="Search for specific keys", command=searchWin)
selButton1.grid(row=1, column=1)
selButton2.grid(row=1, column=2)

spacing1 = Frame(frame1, height=10)
spacing2 = Frame(frame1, width=10)
spacing3 = Frame(frame1, width=10)
spacing1.grid(row=2,columnspan=2)
spacing2.grid(rowspan=3)
spacing3.grid(column=3, rowspan=3)
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

#keyCount = StringVar()
#infoText = Label(frame3, textvariable=keyCount, font=("", 11 , "bold"))
#infoText.grid(column=1)
proBar = ttk.Progressbar(frame3, orient=HORIZONTAL, length=300, mode="determinate", maximum=maxcount)
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

#Launches the GUI
root.mainloop()
