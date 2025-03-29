from tables import *
from CipherEngine import Strumok

class StrumokSimulator(Strumok):
    def __init__(self, key: list, key_size: int, iv: list):
        super().__init__(key, key_size, iv)
        self.state_history = []
    
    def log_state(self):
        self.state_history.append((self.S.copy(), self.r.copy()))
    
    def next_with_logging(self) -> list:
        stream = [0] * 16
        for i in range(16):
            self.S[i] = (strumok_alpha_mul(self.S[i]) ^ self.S[(i + 13) % 16] ^ strumok_alpha_mul_inv(self.S[(i - 5) % 16])) & MASK
            temp_FSM = (self.r[1] + self.S[(i + 13) % 16]) & MASK
            self.r[1] = strumok_function_T(self.r[0])
            self.r[0] = temp_FSM
            stream[i] = ((self.r[0] + self.S[i]) & MASK) ^ self.r[1] ^ self.S[(i + 1) % 16]
        
        self.log_state()
        return stream

# example attack scenario with fixed data
def simulate_attack(rounds=11):
    key = [0x0123456789ABCDEF] * 8 
    iv = [0x0011223344556677] * 4
    cipher = StrumokSimulator(key, 64, iv)
    
    # simulate rounds to collect state changes
    for _ in range(rounds):
        cipher.next_with_logging()
    
    with open("internal_state.txt", 'w') as f:
       for i, (S, r) in enumerate(cipher.state_history):
           f.write(f"Round {i}:\nS = {S}\nr = {r}\n\n")

simulate_attack(11)
