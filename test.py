import streamlit as st
import base64
import random
from typing import Tuple
import json
import os

# Try to import cryptography. If it's missing, fall back to the original XOR implementation
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    AES_AVAILABLE = True
except Exception:
    AES_AVAILABLE = False

# =======================
# Encryption Classes
# =======================

if AES_AVAILABLE:
    class SimpleSymmetricEncryption:
        """AES-256 GCM symmetric encryption using a password-derived key (PBKDF2).

        Behaviour:
        - The user still supplies a text "key" (password) in the UI as before.
        - For encryption, a random salt (16 bytes) and a random nonce (12 bytes) are generated.
        - A 32-byte key is derived from the password using PBKDF2-HMAC-SHA256.
        - AES-GCM (authenticated) is used to encrypt; the resulting ciphertext (which includes the tag)
          plus the salt and nonce are returned as a JSON string:
            {"salt": "<b64>", "nonce": "<b64>", "ciphertext": "<b64>"}
        - decrypt() expects that JSON string and performs the reverse derivation and AES-GCM decrypt.
        - This keeps the external API (encrypt/decrypt taking/returning str) unchanged for the rest of the app/UI.
        """

        # PBKDF2 parameters
        _PBKDF2_ITERATIONS = 390000  # reasonably strong default; adjust as needed
        _SALT_SIZE = 16
        _NONCE_SIZE = 12  # recommended for AESGCM

        def __init__(self, key: str):
            # keep the provided string and also store its bytes form for KDF
            if not isinstance(key, str):
                raise TypeError("key must be a string")
            self.password = key.encode('utf-8')  # used for PBKDF2

        def _derive_key(self, salt: bytes) -> bytes:
            """Derive a 32-byte AES key from the password and salt using PBKDF2-HMAC-SHA256."""
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits
                salt=salt,
                iterations=self._PBKDF2_ITERATIONS,
            )
            return kdf.derive(self.password)

        def encrypt(self, plaintext: str) -> str:
            """Encrypt plaintext using AES-256-GCM.

            Returns a JSON string containing base64-encoded salt, nonce and ciphertext.
            """
            if not isinstance(plaintext, str):
                raise TypeError("plaintext must be a string")

            # Generate salt and derive key
            salt = os.urandom(self._SALT_SIZE)
            key = self._derive_key(salt)

            # Generate nonce and encrypt
            nonce = os.urandom(self._NONCE_SIZE)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), associated_data=None)

            payload = {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ct).decode('utf-8'),
            }
            return json.dumps(payload)

        def decrypt(self, ciphertext: str) -> str:
            """Decrypt the JSON string produced by encrypt() and return the plaintext string."""
            if not isinstance(ciphertext, str):
                raise TypeError("ciphertext must be a string")

            try:
                payload = json.loads(ciphertext)
                salt = base64.b64decode(payload['salt'])
                nonce = base64.b64decode(payload['nonce'])
                ct = base64.b64decode(payload['ciphertext'])
            except Exception as e:
                raise ValueError("Invalid ciphertext format. Expected JSON with salt/nonce/ciphertext.") from e

            key = self._derive_key(salt)
            aesgcm = AESGCM(key)
            try:
                pt = aesgcm.decrypt(nonce, ct, associated_data=None)
                return pt.decode('utf-8')
            except Exception as e:
                # Bubble up a clear error for the UI to catch
                raise ValueError("Decryption failed. Wrong password or corrupted ciphertext.") from e

else:
    # Fallback to original XOR-based (toy) symmetric encryption if cryptography is not installed
    class SimpleSymmetricEncryption:
        """Simple symmetric encryption using XOR cipher (fallback if cryptography not available)"""

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


# --- UI FUNCTIONS ---
def symmetric_encryption_ui():
    st.subheader("🔑 Symmetric Encryption")

    if not AES_AVAILABLE:
        st.warning(
            "cryptography package not found. Symmetric encryption is using the fallback XOR implementation. "
            "To enable AES-256-GCM, install the 'cryptography' package (pip install cryptography)."
        )

    key_encrypt = st.text_input("Enter Secret Key for Encryption", key="sym_key_encrypt", type="password")
    message = st.text_area("Enter Message", key="sym_msg")

    # Use session state to keep encrypted message visible after decryption key entry
    if 'encrypted_message' not in st.session_state:
        st.session_state['encrypted_message'] = ""

    encrypt_clicked = st.button("Encrypt", key="sym_encrypt")
    if encrypt_clicked:
        if not key_encrypt or not message:
            st.error("Please enter both secret key and message.")
        else:
            cipher = SimpleSymmetricEncryption(key_encrypt)
            encrypted = cipher.encrypt(message)
            st.session_state['encrypted_message'] = encrypted
            st.success("✅ Encrypted Message:")
            st.code(encrypted, language="text")
    elif st.session_state['encrypted_message']:  # Show the last encrypted message if present
        st.success("✅ Encrypted Message:")
        st.code(st.session_state['encrypted_message'], language="text")

    st.markdown("---")

    # --- Decryption Section ---
    st.markdown("### Decryption")
    key_decrypt = st.text_input("Enter Secret Key for Decryption", key="sym_key_decrypt", type="password")
    ciphertext = st.text_area("Enter Encrypted Message", key="sym_ciphertext", value=st.session_state['encrypted_message'])

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

    # Use session state to persist generated keys
    if "rsa_public_key" not in st.session_state or "rsa_private_key" not in st.session_state:
        rsa = SimpleRSA()
        public_key, private_key = rsa.generate_keypair()
        st.session_state["rsa_public_key"] = public_key
        st.session_state["rsa_private_key"] = private_key

    public_key = st.session_state["rsa_public_key"]
    private_key = st.session_state["rsa_private_key"]

    st.write("🔸 Public Key:", public_key)

    # --- Show/mask private key ---
    if "show_private_key_asym" not in st.session_state:
        st.session_state["show_private_key_asym"] = False

    if not st.session_state["show_private_key_asym"]:
        pk_str = str(private_key)
        st.write("🔸 Private Key:", "•" * len(pk_str))
    else:
        st.write("🔸 Private Key:", private_key)
    # Button to reveal/hide private key (directly under key)
    if st.button("Show Private Key" if not st.session_state["show_private_key_asym"] else "Hide Private Key", key="show_private_key_asym_button"):
        st.session_state["show_private_key_asym"] = not st.session_state["show_private_key_asym"]

    st.markdown("**Enter Message:**")
    message = st.text_area("", key="rsa_msg")

    encrypt_clicked = st.button("Encrypt with Public Key", key="rsa_encrypt")
    if encrypt_clicked:
        rsa = SimpleRSA()
        encrypted = rsa.encrypt(message, public_key)
        st.success("✅ Encrypted Message (Numbers):")
        st.code(json.dumps(encrypted), language="json")

    st.markdown("**Paste Encrypted Data (Numbers, JSON list):**")
    encrypted_numbers_input = st.text_area("", key="rsa_encrypted_numbers")
    decrypt_numbers_clicked = st.button("Decrypt Numbers with Private Key", key="rsa_decrypt_numbers")
    if decrypt_numbers_clicked:
        try:
            encrypted_numbers = json.loads(encrypted_numbers_input)
            rsa = SimpleRSA()
            decrypted = rsa.decrypt(encrypted_numbers, private_key)
            st.success("✅ Decrypted Message from Numbers:")
            st.code(decrypted, language="text")
        except Exception:
            st.error("Invalid encrypted data format or not a JSON list of numbers.")


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

    # --- Show/mask private key ---
    if "show_private_key" not in st.session_state:
        st.session_state["show_private_key"] = False

    if not st.session_state["show_private_key"]:
        pk_str = str(private_key)
        st.write("🔹 Private Key:", "•" * len(pk_str))
    else:
        st.write("🔹 Private Key:", private_key)
    # Button to reveal/hide private key (directly under key)
    if st.button("Show Private Key" if not st.session_state["show_private_key"] else "Hide Private Key", key="show_private_key_button"):
        st.session_state["show_private_key"] = not st.session_state["show_private_key"]

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


# --- MAIN DRIVER ---
if mode == "Symmetric Encryption":
    symmetric_encryption_ui()
elif mode == "Asymmetric Encryption (RSA)":
    asymmetric_encryption_ui()
else:
    hybrid_encryption_ui()
