# Walletaid
This script is designed to extract private keys from wallet files created by Bitcoin Core **or** most full node wallets based on the same codebase.
### Installation
1. Install Python 3 (if not installed)
2. Download ZIP of this repository and unzip.
### Usage
```
python walletaid.py "filepath" pubkeyprefix privkeyprefix [-a address] [-c] [-h]

positional arguments:
  filepath       Path to wallet file (use "")
  pubkeyprefix   public key prefix in hex (e.g. 00 for bitcoin)
  privkeyprefix  private key prefix in hex (e.g. 80 for bitcoin)

optional arguments:
  -a address     address to search the key for
  -c             check if found private key really matches public key (much slower)
  -h, --help     show this help message and exit
 ```
1. Enter password if prompted and press enter.
2. Open "DUMP.txt" to see the recovered keys.
### pubkeyprefix and privkeyprefix
Often found in the /src/chainparams.cpp file in the source code of the coin the wallet is for, typically pubkeyprefix is the Ctrl+F result for ```base58Prefixes[PUBKEY_ADDRESS]``` and the privkeyprefix should be close below as ```base58Prefixes[SECRET_KEY]```.

The value might be hexadecimal or an integer, if it's an integer it must be converted to hexadecimal before being used as a parameter.

Here is a list of a few prefixes given as examples:
- **Bitcoin:** 00 80
- **Litecoin:** 30 b0
- **Dogecoin:** 1e 9e
- **Garlicoin:** 26 b0
- **Reddcoin:** 3d bd
- **ZCash (t1):** 1cb8 80
- **Ravencoin:** 3C 80
- **Neoxa:** 26 70
### Address search
Using ```-a address``` you can search for an address to retrieve the key for by replacing ```address``` for the address to search for, if the wallet is very large this might be a lot quicker.
### Key checking
The ```-c``` flag can be added to check that the found private key truly matches the address it's paired with in the wallet file. This will severely impact performance as deriving public keys from private keys is an expensive operation, but it's useful to sort out invalid data and corrupted keys.
