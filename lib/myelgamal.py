from Crypto.Util.number import getPrime, getRandomInteger, getStrongPrime, getRandomRange
import cryptography.hazmat.primitives.asymmetric.dsa as dsa


def compute_mod_inverse(q, K):
    num1: int = q
    num2: int = K
    coefs: list = list()
    while num2 != 1:
        tmp: int = num1 % num2
        coefs.append(num1 // num2)
        num1 = num2
        num2 = tmp

    coef1: int = 1
    coef2: int = -coefs[-1]
    i: int = len(coefs) - 2
    while i >= 0:
        tmp: int = coef2
        coef2 = coefs[i] * (-coef2) + coef1
        coef1 = tmp
        i = i - 1
    if coef2 < 0:
        return q + coef2
    else:
        return coef2

class ElgamalPrivateKey:
    def __init__(self, q : int, a: int, Xa: int, size: int):
        self.q = q
        self.a = a
        self.Xa = Xa
        self.size = size
        self.public_key = ElgamalPublicKey(q, a, self._calculate_Ya(), size)



    def _calculate_Ya(self) -> int:
        return pow(self.a, self.Xa, self.q)

    def decrypt(self, ciphertext: bytes)-> bytes:
        c1: int = int.from_bytes(ciphertext[:self.size // 8], "big")
        K: int = pow(c1, self.Xa, self.q)
        Km1: int = self._compute_mod_inverse(K)
        if(K * Km1 % self.q == 1):
            print("Yea inverse!")
        i : int = self.size // 8
        msg: bytes = b''

        while i < len(ciphertext):
          c2: int = int.from_bytes(ciphertext[i: i + self.size // 8], "big")
          m_int: int = c2 * Km1 % self.q
          m_len: int = (len(str(hex(m_int))) - 2) // 2 + (len(str(hex(m_int))) - 2) % 2
          m_bytes: bytes = m_int.to_bytes(m_len, "big")
          msg += m_bytes
          i = i + self.size // 8
        return msg

    def _compute_mod_inverse(self, K):
        num1: int = self.q
        num2: int = K
        coefs: list = list()
        while num2 != 1:
            tmp: int = num1 % num2
            coefs.append(num1 // num2)
            num1 = num2
            num2 = tmp
        # print(coefs)
        coef1: int = 1
        coef2: int = -coefs[-1]
        i: int = len(coefs) - 2
        while i >= 0:
            tmp: int = coef2
            coef2 = coefs[i] * (-coef2) + coef1
            coef1 = tmp
            i = i - 1
        if coef2 < 0:
            return self.q + coef2
        else:
            return coef2

class ElgamalPublicKey:

    def __init__(self, q: int, a: int, Ya: int, size: int):
        self.q = q
        self.a = a
        self.Ya = Ya
        self.size = size

    def _calculate_one_time_k(self) -> int:
        return getRandomRange(0, self.q)

    def split_message(self, message: bytes) -> list:
        message_list: list = list()
        i: int = 0
        num_of_bytes: int = self.size // 8 - 1
        while i < len(message):
            if len(message) > i + num_of_bytes:
                message_list.append(message[i:i + num_of_bytes])
            else:
                message_list.append(message[i:])
            i = i + num_of_bytes

        return message_list

    def encrypt(self, message: bytes)->bytes:
        k: int = self._calculate_one_time_k()
        K :int = pow(self.Ya, k, self.q)
        "Nek bude isto k za svako parce poruke"
        message_list: list = self.split_message(message)
        c1: int = pow(self.a, k, self.q)
        ciphertext_list: list = list()
        ciphertext_list.append(c1.to_bytes(self.size // 8, 'big'))
        for msg in message_list:
            msg_int: int = int.from_bytes(msg, "big")
            c2: int = (K * msg_int) % self.q
            ciphertext_list.append(c2.to_bytes(self.size // 8, 'big'))

        ciphertext: bytes = b''
        for msg in ciphertext_list:
            ciphertext += msg
        return ciphertext
class Elgamal:
    @staticmethod
    def generate_private_key(key_size: int) -> ElgamalPrivateKey:
        q : int = getPrime(key_size)
        a : int = Elgamal._calucalate_a(q)
        Xa = getRandomRange(2, q - 1)
        Ya = Elgamal._calculate_Ya(q, a, Xa)
        return ElgamalPrivateKey(q, a, Xa, key_size)

    #Ni ovo ne treba
    @staticmethod
    def _calculate_Ya(q: int, a: int, Xa: int) -> int:
        return pow(a, Xa, q)


    @staticmethod
    def _calucalate_a(q: int) -> int:

        res: int = getRandomRange(2, q - 1)
        while not Elgamal.is_prime_root(res, q):
            res: int = getRandomRange(2 , q - 1)
        return res

    @staticmethod
    def is_prime_root(a: int, q: int):
        return pow(a, q >> 1, q) == q - 1

    #Ne treba, zna sam da se ne muci
    @staticmethod
    def mod_pow_efficiently(base: int, exponent: int, modulus: int):
        result: int = 1
        powed_base: int = base

        while exponent != 0:
            if exponent & 1:
                result = result * powed_base % modulus
            powed_base = pow(powed_base, 2, modulus)
            exponent = exponent >> 1
        return result



if __name__ == "__main__":

    private_key: ElgamalPrivateKey = Elgamal.generate_private_key(1024)

    message: str = "Ja sam mika!"
    byte_msg: bytes = bytes(message, 'utf-8')
    # print(byte_msg)
    ciphertext1: bytes = private_key.public_key.encrypt(byte_msg)

    print(ciphertext1)
    print(private_key.decrypt(ciphertext1))


    message2: str = "Ja sam mika!" * 30
    byte_msg2: bytes = bytes(message2, 'utf-8')
    # print(byte_msg2)
    ciphertext2: bytes = private_key.public_key.encrypt(byte_msg2)

    print(ciphertext2)
    print(private_key.decrypt(ciphertext2))


    # for i in range(2, 1999):
    #     inv = compute_mod_inverse(1999, i)
    #     if(i*inv % 1999 != 1):
    #         print(f"Aaaaa {i}")
