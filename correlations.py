import random
from CipherEngine import Strumok

class FCorrelations: 

    def __init__(self, key: list, iv: list, key_size: int):
        self.key = key
        self.iv = iv
        self.key_size = key_size
        self.S = [0] * 16 
        self.r = [0, 0]
        self.strumok = Strumok(key, key_size, iv)

    def generate_functional_relations(self):
        algebraic_relations = []
        connection_relations = []
        
        # monitoring changes to create correlations
        for i in range(11):
            algebraic_relations.append(self.generate_algebraic_relation(i))
            connection_relations.append(self.generate_connection_relation(i))

        return algebraic_relations, connection_relations

    def generate_algebraic_relation(self, step: int):
        terms = [f'X{step}*X{(step+1) % 7} + X{(step+2) % 7}*X{(step+3) % 7}',
        f'X{(step+4) % 7} + X{(step+5) % 7}*X{(step+6) % 7}',
        f'X{(step+1) % 7} xor X{(step+3) % 7} + X{(step+5) % 7}',
        f'X{(step+2) % 7} xor X{(step+4) % 7}*X{(step+6) % 7}',
        f'X{(step+1) % 7} + X{(step+4) % 7}*X{(step+6) % 7} xor X{(step+5) % 7}',
        f'X{(step+4) % 7} xor X{(step+2) % 7}*X{(step+1) % 7} + X{(step+3) % 7}',
        f'X{(step+5) % 7} xor X{(step+6) % 7}*X{(step+4) % 7} + X{(step+2) % 7}',
        f'X{(step+1) % 7} + X{(step+3) % 7}*X{(step+5) % 7} xor X{(step+2) % 7}',
        f'X{(step+6) % 7} xor X{(step+1) % 7}*X{(step+4) % 7} + X{(step+5) % 7}',]
        return ' + '.join(terms)

    def generate_connection_relation(self, step: int):
        return f'X{(step+2) % 7} => X{(step+4) % 7}, X{(step+5) % 7} => X{(step+6) % 7}'

    # structured according to the manual on the Autoguess github 
    def save_relations_to_file(self, algebraic_relations, connection_relations, filename="frelations.txt"):
        with open(filename, 'w') as f:
            f.write("algebraic relations\n")
            for relation in algebraic_relations:
                f.write(f'{relation}\n')

            f.write("connection relations\n")
            for relation in connection_relations:
                f.write(f'{relation}\n')

            f.write("known\n")
            f.write("X2\n")  # known variable

            f.write("target\n")
            targets = ["X1", "X3", "X4", "X5", "X6"]  # add targets
            for target in targets:
                f.write(f"{target}\n")

            f.write("end\n")

if __name__ == "__main__":
    key = [random.randint(0, 0xFFFFFFFFFFFFFFFF) for _ in range(8)]
    iv = [random.randint(0, 0xFFFFFFFFFFFFFFFF) for _ in range(4)]

    analyzer = FCorrelations(key, iv, 64)
    algebraic_relations, connection_relations = analyzer.generate_functional_relations()
    analyzer.save_relations_to_file(algebraic_relations, connection_relations)
