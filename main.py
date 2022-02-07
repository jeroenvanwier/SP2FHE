import secrets


class DGHVParams:
    def __init__(self, q_size: int, r_size: int):
        self.q_size = q_size
        self.r_size = r_size
        self.largest_q = 2 ** q_size
        self.largest_r = 2 ** r_size


class DGHVPrivateKey:
    def __init__(self, params: DGHVParams):


class DGHVPublicKey:
    def __init__(self, private_key: int, params: DGHVParams):


def encrypt(plaintext: int, public_key: int, params: DGHVParams):
    r = secrets.randbelow(params.largest_r)
    q = secrets.randbelow(params.largest_q)
    return public_key * q + 2 * r + plaintext


def decrypt(ciphertext: int, private_key: int, params: DGHVParams):
    return (ciphertext % private_key) % 2


if __name__ == '__main__':
    pass
