from tables import *


class Strumok:
    def __init__(self, key: list, key_size: int, iv: list):
        self.key_size = key_size
        self.iv = iv
        self.key = key
        self.S = [0] * 16  # LFSR state
        self.r = [0, 0]  # FSM registers
        self.init_state()

    def init_state(self):
        if self.key_size == 32:
            self.S[0] = self.key[3] ^ self.iv[0]
            self.S[1] = self.key[2]
            self.S[2] = self.key[1] ^ self.iv[1]
            self.S[3] = self.key[0] ^ self.iv[2]
            self.S[4] = self.key[3]
            self.S[5] = self.key[2] ^ self.iv[3]
            self.S[6] = (~self.key[1]) & MASK
            self.S[7] = (~self.key[0]) & MASK
            self.S[8] = self.key[3]
            self.S[9] = self.key[2]
            self.S[10] = (~self.key[1]) & MASK
            self.S[11] = self.key[0]
            self.S[12] = self.key[3]
            self.S[13] = (~self.key[2]) & MASK
            self.S[14] = self.key[1]
            self.S[15] = (~self.key[0]) & MASK
        elif self.key_size == 64:
            self.S[0] = self.key[7] ^ self.iv[0]
            self.S[1] = self.key[6]
            self.S[2] = self.key[5]
            self.S[3] = self.key[4] ^ self.iv[1]
            self.S[4] = self.key[3]
            self.S[5] = self.key[2] ^ self.iv[2]
            self.S[6] = self.key[1]
            self.S[7] = (~self.key[0]) & MASK
            self.S[8] = self.key[4] ^ self.iv[3]
            self.S[9] = (~self.key[6]) & MASK
            self.S[10] = self.key[5]
            self.S[11] = (~self.key[7]) & MASK
            self.S[12] = self.key[3]
            self.S[13] = self.key[2]
            self.S[14] = (~self.key[1]) & MASK
            self.S[15] = self.key[0]
        else:
            raise ValueError("Unsupported key size")

        self.r = [0, 0]

        for _ in range(2):
            for i in range(16):
                output_FSM = ((self.r[0] + self.S[(i - 1) % 16]) & MASK) ^ self.r[1]
                self.S[i] = (strumok_alpha_mul(self.S[i]) ^ self.S[(i + 13) % 16] ^ strumok_alpha_mul_inv(
                    self.S[(i - 5) % 16]) ^ output_FSM) & MASK
                temp_FSM = (self.r[1] + self.S[(i + 13) % 16]) & MASK
                self.r[1] = strumok_function_T(self.r[0])
                self.r[0] = temp_FSM

    def next(self) -> list:
        stream = [0] * 16
        for i in range(16):
            self.S[i] = (strumok_alpha_mul(self.S[i]) ^ self.S[(i + 13) % 16] ^ strumok_alpha_mul_inv(self.S[(i - 5) % 16])) & MASK
            temp_FSM = (self.r[1] + self.S[(i + 13) % 16]) & MASK
            self.r[1] = strumok_function_T(self.r[0])
            self.r[0] = temp_FSM
            stream[i] = ((self.r[0] + self.S[i]) & MASK) ^ self.r[1] ^ self.S[(i + 1) % 16]
        return stream

    def next_xor(self, in_bytes: list) -> list:
        stream = [0] * 16
        for i in range(16):
            self.S[i] = (strumok_alpha_mul(self.S[i]) ^ self.S[(i + 13) % 16] ^ strumok_alpha_mul_inv(self.S[(i - 5) % 16])) & MASK
            temp_FSM = (self.r[1] + self.S[(i + 13) % 16]) & MASK
            self.r[1] = strumok_function_T(self.r[0])
            self.r[0] = temp_FSM
            keystream = ((self.r[0] + self.S[i]) & MASK) ^ self.r[1] ^ self.S[(i + 1) % 16]
            stream[i] = in_bytes[i] ^ keystream
        return stream

    def crypt(self, data: bytes) -> bytes:
        block_size = 128
        out = bytearray()
        idx = 0
        while idx + block_size <= len(data):
            block = [int.from_bytes(data[idx + i*8: idx + (i+1)*8], 'little') for i in range(16)]
            out_block = self.next_xor(block)
            for word in out_block:
                out.extend(word.to_bytes(8, 'little'))
            idx += block_size

        if idx < len(data):
            keystream_words = self.next()
            keystream_bytes = b''.join(word.to_bytes(8, 'little') for word in keystream_words)
            remaining = data[idx:]
            out.extend(bytes(a ^ b for a, b in zip(remaining, keystream_bytes)))

        return bytes(out)