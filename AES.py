import hashlib
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


def Encryption(plain_text, password):
    random = get_random_bytes(AES.block_size)
    pvkey = hashlib.scrypt(password.encode(), salt=random, n=2 ** 14, r=8, p=1, dklen=32)
    conf = AES.new(pvkey, AES.MODE_GCM)
    cipher_text, label = conf.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {'ciphered': b64encode(cipher_text).decode('utf-8'), 'random': b64encode(random).decode('utf-8'), 'nonce':b64encode(conf.nonce).decode('utf-8'), 'label': b64encode(label).decode('utf-8')}


def Decryption(encyptiondic, password):
    random = b64decode(encyptiondic['random'])
    cipher_text = b64decode(encyptiondic['ciphered'])
    nonce = b64decode(encyptiondic['nonce'])
    label = b64decode(encyptiondic['label'])
    pvkey = hashlib.scrypt(password.encode(), salt=random, n=2 ** 14, r=8, p=1, dklen=32)
    cipher = AES.new(pvkey, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, label)
    return decrypted


if __name__ == '__main__':
    password = input("Password: ")
    plain_text = input("Enter Plain Text: ")
    encrypted = Encryption(plain_text, password)
    print(encrypted)
    decrypted = Decryption(encrypted, password)
    print("Decrypted Text That You Entered Before:", bytes.decode(decrypted))

#get helped from https://medium.com/wearesinch/building-aes-128-from-the-ground-up-with-python-8122af44ebf9, https://qvault.io/cryptography/aes-256-cipher-python-cryptography-examples/