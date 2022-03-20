from typing import List
import random
import secrets
import sys
import pickle


class DGHVParams:
    """Container class for the parameters used by the DGHV scheme."""

    def __init__(self, gamma: int, eta: int, rho: int, tau: int, rho_prime: int, sec: int, alpha: int):
        self.gamma = gamma
        self.eta = eta
        self.rho = rho
        self.tau = tau
        self.rho_prime = rho_prime
        self.sec = sec
        self.alpha = alpha

    def pick_p(self):
        """Pick a random prime p of size eta bits, using the Sage random_prime function."""
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
    """Wrapper class for the private key"""

    def __init__(self, p: int):
        self.p = p

    def __repr__(self):
        return str(self)

    def __str__(self):
        return str(self.p)


class DGHVPublicKey:
    """Wrapper class for the public key. Contains the initial seed for the pseudorandom generator to generate the chis, the x_0 and the list of deltas."""

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
    """Key generator function for the DGHV scheme."""
    # Create the x_0 noiseless ciphertext.
    p = params.pick_p()
    q_0 = randbelow((2 ** (params.gamma - 1)) / p) * 2 + 1
    x_0 = q_0 * p
    # Pick a seed for the PRG.
    seed = randbelow(2 ** params.gamma)
    random.seed(a=seed)
    # Generate the chis using the PRG.
    chis = [random.randrange(2 ** params.gamma) for _ in range(params.tau)]
    # Calculate the deltas for the previously-generated chis.
    deltas = [(chi % p) + params.pick_xi(p) * p - params.pick_r()
              for chi in chis]
    # Wrap the keys and return them.
    private_key = DGHVPrivateKey(p)
    public_key = DGHVPublicKey(seed, x_0, deltas)
    return public_key, private_key


def encrypt(plaintext: int, public_key: DGHVPublicKey, params: DGHVParams):
    """Encryption function for the DGHV scheme."""
    # Pick some random noise using the rho' parameter
    r = params.pick_r(prime=True)
    sum = 0
    random.seed(public_key.seed)
    for i in range(1, params.tau + 1):
        # One-by-one reconstruct the x's and add them together weighted by random b's
        b = randbelow(2 ** params.alpha)
        chi = random.randrange(2 ** params.gamma)
        x = chi - public_key.delta(i)
        sum = mod(sum + b * x, public_key.x_0)
    # Use the sum to encrypt the plaintext
    return mod(plaintext + 2 * r + 2 * sum, public_key.x_0)


def decrypt(ciphertext: int, private_key: DGHVPrivateKey, params: DGHVParams):
    """Decryption function for the DGHV scheme. Implements the non-squashed basic decryption."""
    return mod(ciphertext, private_key.p) % 2


if __name__ == '__main__':
    # We use the 'toy example' scheme parameters to facilitate timely execution. See the README file for the explaination of all the commands.
    params = DGHVParams(160000, 1088, 16, 4096, 64, 42, 16)
    if "keygen" in sys.argv:
        pk, sk = keygen(params)
        pickle.dump(pk, open("key.public", "wb"))
        pickle.dump(sk, open("key.private", "wb"))
    elif "test_correctness" in sys.argv:
        pk = pickle.load(open("key.public", "rb"))
        sk = pickle.load(open("key.private", "rb"))
        TOTAL_TESTS = 10
        for i in range(TOTAL_TESTS):
            plaintext = secrets.choice([0, 1])
            decryption = decrypt(encrypt(plaintext, pk, params), sk, params)
            if plaintext != decryption:
                print(f"Correctness failed: {plaintext} -> {decryption}")
            else:
                print(f"Succesfully completed test {i+1} out of {TOTAL_TESTS}")
    elif "test_adding" in sys.argv:
        pk = pickle.load(open("key.public", "rb"))
        sk = pickle.load(open("key.private", "rb"))
        TOTAL_TESTS = 10
        VALUES_SUMMED = 3
        for i in range(TOTAL_TESTS):
            plaintexts = [secrets.choice([0, 1]) for _ in range(VALUES_SUMMED)]
            ciphertexts = [encrypt(plaintext, pk, params)
                           for plaintext in plaintexts]
            cipher_sum = sum(ciphertexts)
            plain_sum = decrypt(cipher_sum, sk, params)
            correct_sum = sum(plaintexts) % 2
            print(
                f"Test {i+1} of {TOTAL_TESTS}: Sum of {''.join([str(p) for p in plaintexts])} is {plain_sum}, {'correct' if correct_sum == plain_sum else 'incorrect'}")
    elif "test_multiplying" in sys.argv:
        pk = pickle.load(open("key.public", "rb"))
        sk = pickle.load(open("key.private", "rb"))
        TOTAL_TESTS = 10
        for i in range(TOTAL_TESTS):
            plaintexts = [secrets.choice([0, 1]) for _ in range(2)]
            ciphertexts = [encrypt(plaintext, pk, params)
                           for plaintext in plaintexts]
            cipher_mul = ciphertexts[0] * ciphertexts[1]
            plain_mul = decrypt(cipher_mul, sk, params)
            correct_mul = plaintexts[0] * plaintexts[1]
            print(
                f"Test {i+1} of {TOTAL_TESTS}: Product of {''.join([str(p) for p in plaintexts])} is {plain_mul}, {'correct' if correct_mul == plain_mul else 'incorrect'}")
    else:
        print("Run with:\n-'keygen' to generate keys\n-'test_correctness' to test correctness of the scheme\n-'test_adding' to test addition of ciphertexts\n-'test_multiplying' to test multiplication of ciphertexts")
