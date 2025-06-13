# Plutus Bitcoin Brute Forcer with Date & Time Spoofing
# Modified by greglong83 for feature request: spoofable RNG seed but all the credit goes to the original creator below
# Original: https://github.com/Isaacdelly/Plutus

import os
import pickle
import hashlib
import binascii
import multiprocessing
import argparse
import time
from ellipticcurve.privateKey import PrivateKey

DATABASE = r'database/MAR_23_2019/'

def parse_args():
    parser = argparse.ArgumentParser(description="Plutus Bitcoin Brute Forcer with Date/Time spoofing option")
    parser.add_argument("--spoof-datetime", type=str, default=None,
                        help="Spoof the random number generator seed as a Unix time. Format: 'YYYY-MM-DD HH:MM:SS'")
    parser.add_argument("--use-deterministic", action="store_true",
                        help="Use deterministic PRNG (random module) seeded with spoofed date/time instead of os.urandom.")
    return parser.parse_args()

def get_random_bytes(n, spoofed_time=None, deterministic=False):
    if deterministic and spoofed_time is not None:
        import random
        # Seed once per process
        if not hasattr(get_random_bytes, "_seeded") or not get_random_bytes._seeded:
            random.seed(int(spoofed_time))
            get_random_bytes._seeded = True
        return random.getrandbits(n*8).to_bytes(n, byteorder='big')
    else:
        return os.urandom(n)

def generate_private_key(spoofed_time=None, deterministic=False): 
    """
    Generate a random 32-byte hex integer which serves as a randomly 
    generated Bitcoin private key.
    Supports spoofed date/time via deterministic PRNG if enabled.
    """
    return binascii.hexlify(get_random_bytes(32, spoofed_time, deterministic)).decode('utf-8').upper()

def private_key_to_public_key(private_key):
    """
    Accept a hex private key and convert it to its respective public key. 
    """
    pk = PrivateKey().fromString(bytes.fromhex(private_key))
    return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):
    """
    Accept a public key and convert it to its resepective P2PKH wallet address.
    """
    output = []
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    var = hashlib.new('ripemd160')
    encoding = binascii.unhexlify(public_key.encode())
    var.update(hashlib.sha256(encoding).digest())
    var_encoded = ('00' + var.hexdigest()).encode()
    digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
    var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
    count = [char != '0' for char in var_hex].index(True) // 2
    n = int(var_hex, 16)
    while n > 0:
        n, remainder = divmod(n, 58)
        output.append(alphabet[remainder])
    for i in range(count): output.append(alphabet[0])
    return ''.join(output[::-1])

def process(private_key, public_key, address, database):
    """
    Accept an address and query the database. If the address is found in the 
    database, then assume it has a balance and write wallet data to disk.
    """
    if address in database[0] or \
       address in database[1] or \
       address in database[2] or \
       address in database[3]:
        with open('plutus.txt', 'a') as file:
            file.write('hex private key: ' + str(private_key) + '\n' +
                   'WIF private key: ' + str(private_key_to_WIF(private_key)) + '\n' +
                   'public key: ' + str(public_key) + '\n' +
                   'address: ' + str(address) + '\n\n')
    else: 
        print(str(address))

def private_key_to_WIF(private_key):
    """
    Convert the hex private key into Wallet Import Format for easier wallet 
    importing.
    """
    digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
    var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
    var = binascii.unhexlify('80' + private_key + var[0:8])
    alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = pad = 0
    result = ''
    for i, c in enumerate(var[::-1]): value += 256**i * c
    while value >= len(alphabet):
        div, mod = divmod(value, len(alphabet))
        result, value = chars[mod] + result, div
    result = chars[value] + result
    for c in var:
        if c == 0: pad += 1
        else: break
    return chars[0] * pad + result

def main(database, spoofed_time=None, deterministic=False):
    """
    Main brute force pipeline loop.
    """
    while True:
        private_key = generate_private_key(spoofed_time, deterministic)
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)
        process(private_key, public_key, address, database)

if __name__ == '__main__':
    """
    Parse arguments, load database, and launch parallel brute forcers.
    """
    args = parse_args()
    if args.spoof_datetime:
        try:
            spoofed_time = time.mktime(time.strptime(args.spoof_datetime, '%Y-%m-%d %H:%M:%S'))
        except Exception as e:
            print("Invalid --spoof-datetime format. Use 'YYYY-MM-DD HH:MM:SS'.")
            exit(1)
    else:
        spoofed_time = None

    deterministic = args.use_deterministic and spoofed_time is not None

    database = [set() for _ in range(4)]
    count = len(os.listdir(DATABASE))
    half = count // 2
    quarter = half // 2
    for c, p in enumerate(os.listdir(DATABASE)):
        print('\rreading database: ' + str(c + 1) + '/' + str(count), end = ' ')
        with open(DATABASE + p, 'rb') as file:
            if c < half:
                if c < quarter: database[0] = database[0] | pickle.load(file)
                else: database[1] = database[1] | pickle.load(file)
            else:
                if c < half + quarter: database[2] = database[2] | pickle.load(file)
                else: database[3] = database[3] | pickle.load(file)
    print('DONE')

    for cpu in range(multiprocessing.cpu_count()):
        multiprocessing.Process(target=main, args=(database, spoofed_time, deterministic)).start()
