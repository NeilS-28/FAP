import streamlit as st
import base64
import random
from typing import Tuple
import json

# =======================
# Encryption Classes
# =======================
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

    def _gcd(self, a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a: int, m: int) -> int:
        if self._gcd(a, m) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % m

    def _is_prime(self, n: int) -> bool:
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def _generate_prime(self, bits: int = 8) -> int:
        while True:
            candidate = random.getrandbits(bits)
            if candidate > 1 and self._is_prime(candidate):
                return candidate

    def generate_keypair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
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
        self.public_key = (e, n)
        self.private_key = (d, n)
        return self.public_key, self.private_key

    def encrypt(self, message: str, public_key: Tuple[int, int]) -> list:
        e, n = public_key
        return [pow(ord(char), e, n) for char in message]

    def decrypt(self, ciphertext: list, private_key: Tuple[int, int]) -> str:
        d, n = private_key
        return ''.join(chr(pow(num, d, n)) for num in ciphertext)


class HybridEncryption:
    """Hybrid encryption combining symmetric and asymmetric encryption"""

    def __init__(self):
        self.rsa = SimpleRSA()

    def generate_session_key(self, length: int = 16) -> str:
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return ''.join(random.choice(chars) for _ in range(length))

    def hybrid_encrypt(self, message: str, public_key: Tuple[int, int]) -> dict:
        session_key = self.generate_session_key()
        symmetric_cipher = SimpleSymmetricEncryption(session_key)
        encrypted_message = symmetric_cipher.encrypt(message)
        encrypted_session_key = self.rsa.encrypt(session_key, public_key)
        return {
            'encrypted_message': encrypted_message,
            'encrypted_session_key': encrypted_session_key
        }

    def hybrid_decrypt(self, encrypted_data: dict, private_key: Tuple[int, int]) -> str:
        session_key = self.rsa.decrypt(encrypted_data['encrypted_session_key'], private_key)
        symmetric_cipher = SimpleSymmetricEncryption(session_key)
        return symmetric_cipher.decrypt(encrypted_data['encrypted_message'])


# =======================
# Streamlit App UI
# =======================

st.set_page_config(page_title="Encryption & Decryption App", page_icon="🔐", layout="wide")

st.markdown("<h1 style='text-align:center;color:#1f77b4;'>🔐 Encryption & Decryption App</h1>", unsafe_allow_html=True)
st.sidebar.title("Choose Encryption Type")
mode = st.sidebar.selectbox("Select encryption method:", ["Symmetric Encryption", "Asymmetric Encryption (RSA)", "Hybrid Encryption"])

def symmetric_encryption_ui():
    st.subheader("🔑 Symmetric Encryption (XOR)")

    # --- Encryption Section ---
    st.markdown("### Encryption")
    key_encrypt = st.text_input("Enter Secret Key for Encryption", key="sym_key_encrypt", type="password")
    message = st.text_area("Enter Message", key="sym_msg")

    encrypt_clicked = st.button("Encrypt", key="sym_encrypt")
    encrypted = None
    if encrypt_clicked:
        if not key_encrypt or not message:
            st.error("Please enter both secret key and message.")
        else:
            cipher = SimpleSymmetricEncryption(key_encrypt)
            encrypted = cipher.encrypt(message)
            st.success("✅ Encrypted Message:")
            st.code(encrypted, language="text")

    st.markdown("---")

    # --- Decryption Section ---
    st.markdown("### Decryption")
    key_decrypt = st.text_input("Enter Secret Key for Decryption", key="sym_key_decrypt", type="password")
    ciphertext = st.text_area("Enter Encrypted Message", key="sym_ciphertext")

    decrypt_clicked = st.button("Decrypt", key="sym_decrypt")
    if decrypt_clicked:
        if not key_decrypt or not ciphertext:
            st.error("Please enter both secret key and encrypted message.")
        else:
            cipher = SimpleSymmetricEncryption(key_decrypt)
            try:
                decrypted = cipher.decrypt(ciphertext)
                st.success("✅ Decrypted Message:")
                st.code(decrypted, language="text")
            except Exception:
                st.error("Decryption failed! Possibly wrong key or invalid ciphertext.")

def asymmetric_encryption_ui():
    st.subheader("🔐 Asymmetric Encryption (RSA)")

    if "rsa_public_key" not in st.session_state or "rsa_private_key" not in st.session_state:
        rsa = SimpleRSA()
        public_key, private_key = rsa.generate_keypair()
        st.session_state["rsa_public_key"] = public_key
        st.session_state["rsa_private_key"] = private_key

    public_key = st.session_state["rsa_public_key"]
    private_key = st.session_state["rsa_private_key"]

    st.write("🔸 Public Key:", public_key)
    st.write("🔸 Private Key:", private_key)

    st.markdown("**Enter Message:**")
    message = st.text_area("", key="rsa_msg")

    encrypt_clicked = st.button("Encrypt with Public Key", key="rsa_encrypt")
    if encrypt_clicked:
        rsa = SimpleRSA()
        encrypted = rsa.encrypt(message, public_key)
        st.success("✅ Encrypted Message (Numbers):")
        st.code(json.dumps(encrypted), language="json")

    encrypted_input = st.text_area("Paste Encrypted Message (JSON List):", key="rsa_inp")
    decrypt_clicked = st.button("Decrypt with Private Key", key="rsa_decrypt")
    if decrypt_clicked:
        try:
            encrypted_list = json.loads(encrypted_input)
            rsa = SimpleRSA()
            decrypted = rsa.decrypt(encrypted_list, private_key)
            st.success("✅ Decrypted Message:")
            st.code(decrypted, language="text")
        except Exception:
            st.error("Invalid encrypted data format.")

def hybrid_encryption_ui():
    st.subheader("🧩 Hybrid Encryption")

    if "hybrid_public_key" not in st.session_state or "hybrid_private_key" not in st.session_state:
        hybrid = HybridEncryption()
        public_key, private_key = hybrid.rsa.generate_keypair()
        st.session_state["hybrid_public_key"] = public_key
        st.session_state["hybrid_private_key"] = private_key

    public_key = st.session_state["hybrid_public_key"]
    private_key = st.session_state["hybrid_private_key"]

    st.write("🔹 Public Key:", public_key)
    st.write("🔹 Private Key:", private_key)

    st.markdown("**Enter Message:**")
    message = st.text_area("", key="hybrid_msg")

    encrypt_clicked = st.button("Hybrid Encrypt", key="hybrid_encrypt")
    if encrypt_clicked:
        hybrid = HybridEncryption()
        encrypted_data = hybrid.hybrid_encrypt(message, public_key)
        st.session_state["hybrid_encrypted_data"] = encrypted_data
        st.success("✅ Encrypted Data:")
        st.json(encrypted_data)
        encrypted_json = json.dumps(encrypted_data, indent=2)
        st.code(encrypted_json, language="json")

    encrypted_input = st.text_area("Paste Encrypted JSON:", key="hybrid_inp")
    decrypt_clicked = st.button("Hybrid Decrypt", key="hybrid_decrypt")
    if decrypt_clicked:
        try:
            encrypted_data = json.loads(encrypted_input)
            hybrid = HybridEncryption()
            decrypted = hybrid.hybrid_decrypt(encrypted_data, private_key)
            st.success("✅ Decrypted Message:")
            st.code(decrypted, language="text")
        except Exception:
            st.error("Invalid JSON or decryption error.")

if mode == "Symmetric Encryption":
    symmetric_encryption_ui()
elif mode == "Asymmetric Encryption (RSA)":
    asymmetric_encryption_ui()
else:
    hybrid_encryption_ui()
