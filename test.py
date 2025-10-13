import base64
import random
from typing import Tuple

print("=== Symmetric and Asymmetric Encryption Implementation ===\n")


class SimpleSymmetricEncryption:
    """Simple symmetric encryption using XOR cipher (for demonstration)"""

    def __init__(self, key: str):
        self.key = key.encode('utf-8')

    def _extend_key(self, data_length: int) -> bytes:
        """Extend key to match data length"""
        extended_key = (self.key * (data_length // len(self.key) + 1))[:data_length]
        return extended_key

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using XOR"""
        data = plaintext.encode('utf-8')
        extended_key = self._extend_key(len(data))
        encrypted = bytes(a ^ b for a, b in zip(data, extended_key))
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using XOR"""
        encrypted_data = base64.b64decode(ciphertext.encode('utf-8'))
        extended_key = self._extend_key(len(encrypted_data))
        decrypted = bytes(a ^ b for a, b in zip(encrypted_data, extended_key))
        return decrypted.decode('utf-8')


class SimpleRSA:
    """Simplified RSA implementation for educational purposes"""

    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.n = None

    def _gcd(self, a: int, b: int) -> int:
        """Greatest Common Divisor"""
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int) -> int:
        """Modular multiplicative inverse"""
        if self._gcd(a, m) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % m

    def _is_prime(self, n: int) -> bool:
        """Simple prime check"""
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def _generate_prime(self, bits: int = 8) -> int:
        """Generate a small prime number"""
        while True:
            candidate = random.getrandbits(bits)
            if candidate > 1 and self._is_prime(candidate):
                return candidate

    def generate_keypair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Generate RSA key pair"""
        p = self._generate_prime(8)
        q = self._generate_prime(8)
        while p == q:
            q = self._generate_prime(8)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        while self._gcd(e, phi) != 1:
            e += 2

        d = self._mod_inverse(e, phi)

        self.n = n
        self.public_key = (e, n)
        self.private_key = (d, n)

        return self.public_key, self.private_key

    def encrypt(self, message: str, public_key: Tuple[int, int]) -> list:
        """Encrypt message using public key"""
        e, n = public_key
        encrypted = []
        for char in message:
            encrypted.append(pow(ord(char), e, n))
        return encrypted

    def decrypt(self, ciphertext: list, private_key: Tuple[int, int]) -> str:
        """Decrypt ciphertext using private key"""
        d, n = private_key
        decrypted = ""
        for num in ciphertext:
            decrypted += chr(pow(num, d, n))
        return decrypted


class HybridEncryption:
    """Hybrid encryption combining symmetric and asymmetric encryption"""

    def __init__(self):
        self.rsa = SimpleRSA()
        self.symmetric_cipher = None

    def generate_session_key(self, length: int = 16) -> str:
        """Generate a random session key for symmetric encryption"""
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return ''.join(random.choice(chars) for _ in range(length))

    def hybrid_encrypt(self, message: str, public_key: Tuple[int, int]) -> dict:
        """
        Hybrid encryption process:
        1. Generate random symmetric key
        2. Encrypt message with symmetric key (fast)
        3. Encrypt symmetric key with RSA public key (secure)
        """
        session_key = self.generate_session_key()
        symmetric_cipher = SimpleSymmetricEncryption(session_key)
        encrypted_message = symmetric_cipher.encrypt(message)
        encrypted_session_key = self.rsa.encrypt(session_key, public_key)

        return {
            'encrypted_message': encrypted_message,
            'encrypted_session_key': encrypted_session_key
        }

    def hybrid_decrypt(self, encrypted_data: dict, private_key: Tuple[int, int]) -> str:
        """
        Hybrid decryption process:
        1. Decrypt symmetric key using RSA private key
        2. Use decrypted symmetric key to decrypt the message
        """
        session_key = self.rsa.decrypt(encrypted_data['encrypted_session_key'], private_key)
        symmetric_cipher = SimpleSymmetricEncryption(session_key)
        decrypted_message = symmetric_cipher.decrypt(encrypted_data['encrypted_message'])
        return decrypted_message


# Usage Examples
if __name__ == "__main__":
    # 1. Symmetric Encryption Example
    print("1. SYMMETRIC ENCRYPTION")
    print("-" * 30)
    symmetric_cipher = SimpleSymmetricEncryption("MySecretKey123")
    message = "Hello, this is a secret message!"

    encrypted_msg = symmetric_cipher.encrypt(message)
    decrypted_msg = symmetric_cipher.decrypt(encrypted_msg)

    print(f"Original: {message}")
    print(f"Encrypted: {encrypted_msg}")
    print(f"Decrypted: {decrypted_msg}")
    print(f"Success: {message == decrypted_msg}\n")

    # 2. Asymmetric Encryption Example
    print("2. ASYMMETRIC ENCRYPTION (RSA)")
    print("-" * 35)
    rsa = SimpleRSA()
    public_key, private_key = rsa.generate_keypair()

    message = "Hello RSA!"
    encrypted_rsa = rsa.encrypt(message, public_key)
    decrypted_rsa = rsa.decrypt(encrypted_rsa, private_key)

    print(f"Public Key: {public_key}")
    print(f"Private Key: {private_key}")
    print(f"Original: {message}")
    print(f"Encrypted: {encrypted_rsa}")
    print(f"Decrypted: {decrypted_rsa}")
    print(f"Success: {message == decrypted_rsa}\n")

    # 3. Hybrid Encryption Example
    print("3. HYBRID ENCRYPTION")
    print("-" * 25)
    hybrid = HybridEncryption()
    public_key, private_key = hybrid.rsa.generate_keypair()

    long_message = "This demonstrates hybrid encryption combining RSA security with symmetric efficiency!"

    encrypted_hybrid = hybrid.hybrid_encrypt(long_message, public_key)
    decrypted_hybrid = hybrid.hybrid_decrypt(encrypted_hybrid, private_key)

    print(f"Original: {long_message}")
    print(f"Decrypted: {decrypted_hybrid}")
    print(f"Success: {long_message == decrypted_hybrid}")
