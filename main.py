from cipher import Strumok

def main():
    key = [
        0x0000000000000000,  # K0
        0x0000000000000000,  # K1
        0x0000000000000000,  # K2
        0x8000000000000000  # K3
    ]

    iv = [
        0x0000000000000000,  # IV3
        0x0000000000000000,  # IV2
        0x0000000000000000,  # IV1
        0x0000000000000000  # IV0
    ]

    key_size = 32

    cipher = Strumok(key, key_size, iv)

    keystream = cipher.next()

    expected = [
        0xe442d15345dc66ca,
        0xf47d700ecc66408a,
        0xb4cb284b5477e641,
        0xa2afc9092e4124b0,
        0x728e5fa26b11a7d9,
        0xe6a7b9288c68f972,
        0x70eb3606de8ba44c,
        0xaced7956bd3e3de7,
    ]

    print("Keystream output (first 8 words):")
    for i in range(8):
        ks_word = keystream[i]
        flag = ks_word == expected[i]
        print(f"Z{i}: {ks_word:016x}  Expected: {expected[i]:016x} Result: {flag}")

if __name__ == '__main__':
    main()
