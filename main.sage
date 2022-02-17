from typing import List
import random
import secrets


class DGHVParams:
    def __init__(self, gamma: int, eta: int, rho: int, tau: int, rho_prime: int, sec: int, alpha: int):
        self.gamma = gamma
        self.eta = eta
        self.rho = rho
        self.tau = tau
        self.rho_prime = rho_prime
        self.sec = sec
        self.alpha = alpha

    def pick_p(self):
        """Pick a random prime p of size eta bits"""
        return random_prime(2 ** self.eta, lbound=2 ** (self.eta - 1))

    def pick_r(self, neg: bool = True, prime: bool = False):
        """Pick a random r in range (-2^rho, 2^rho). If neg is False, only positive values are returned. If prime is True, rho' is used in place of rho."""
        largest_r = 2 ** self.rho
        if prime:
            largest_r = 2 ** self.rho_prime
        if neg:
            return randbelow(2 * largest_r) - largest_r
        else:
            return randbelow(largest_r)

    def pick_xi(self, p):
        """Pick a random xi in the range [0, 2^(lambda+eta)/p)."""
        return randbelow((2 ** (self.sec + self.eta))/p)

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"Gamma: {self.gamma}, Eta: {self.eta}, Tau: {self.tau}, Rho: {self.rho}, Rho': {self.rho_prime}, Lambda: {self.sec}, Alpha: {self.alpha}"


class DGHVPrivateKey:
    def __init__(self, p: int):
        self.p = p

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str(self.p)


class DGHVPublicKey:
    def __init__(self, seed: int, x_0: int, deltas: List[int]):
        self.seed = seed
        self.x_0 = x_0
        self.deltas = deltas

    def delta(self, i):
        """Return delta_i for 1<=i<=tau. Note that i is 1-indexed and self.deltas is 0-indexed."""
        return self.deltas[i-1]

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str(self.xs)


def randbelow(v: int):
    """Helper function to call randbelow, which doesn't work with Sage Integers"""
    return secrets.randbelow(int(v))


def mod(z: int, p: int):
    """Reduces z mod p such that -p/2 < result <= p/2"""
    result = z % p
    if result > p / 2:
        result -= p
    return result


def keygen(params: DGHVParams):
    p = params.pick_p()
    q_0 = randbelow((2 ** (params.gamma - 1)) / p) * 2 + 1
    x_0 = q_0 * p
    seed = randbelow(2 ** params.gamma)
    random.seed(a=seed)
    chis = [random.randrange(2 ** params.gamma) for _ in range(params.tau)]
    deltas = [(chi % p) + params.pick_xi(p) * p - params.pick_r()
              for chi in chis]
    private_key = DGHVPrivateKey(p)
    public_key = DGHVPublicKey(seed, x_0, deltas)
    return public_key, private_key


def encrypt(plaintext: int, public_key: DGHVPublicKey, params: DGHVParams):
    r = params.pick_r(prime=True)
    sum = 0
    random.seed(public_key.seed)
    for i in range(1, params.tau + 1):
        b = randbelow(2 ** params.alpha)
        chi = random.randrange(2 ** params.gamma)
        x = chi - public_key.delta(i)
        sum = mod(sum + b * x, public_key.x_0)
    return mod(plaintext + 2 * r + 2 * sum, public_key.x_0)


def decrypt(ciphertext: int, private_key: DGHVPrivateKey, params: DGHVParams):
    return mod(ciphertext, private_key.p) % 2


if __name__ == '__main__':
    params = DGHVParams(200000, 27, 3, 20, 3, 32, 5)
    pk, sk = keygen(params)
    for i in range(1000):
        plaintext = secrets.choice([0, 1])
        decryption = decrypt(encrypt(plaintext, pk, params), sk, params)
        if plaintext != decryption:
            print(f"Correctness failed: {plaintext} -> {decryption}")
