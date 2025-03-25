from CipherEngine import Strumok

def main():
    key = [
        0x0000000000000000,  # K0
        0x0000000000000000,  # K1
        0x0000000000000000,  # K2
        0x8000000000000000  # K3
    ]

    iv = [
        0x0000000000000000,  # IV0
        0x0000000000000000,  # IV1
        0x0000000000000000,  # IV2
        0x0000000000000000  # IV3
    ]

    key_size = 32

    encrypt_cipher = Strumok(key, key_size, iv)
    decrypt_cipher = Strumok(key, key_size, iv)

    plaintext = b"Hello, world! Let's check how Strumok works."

    ciphertext = encrypt_cipher.crypt(plaintext)
    decrypted = decrypt_cipher.crypt(ciphertext)

    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Decrypted: {decrypted}")

if __name__ == '__main__':
    main()
