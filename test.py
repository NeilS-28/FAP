import streamlit as st
import base64
import random
from typing import Tuple
import json

# Set page config
st.set_page_config(
    page_title="Encryption & Decryption App",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #ff7f0e;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        margin: 1rem 0;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# [Include all your encryption classes here - SimpleSymmetricEncryption, SimpleRSA, HybridEncryption]

def main():
    st.markdown('<h1 class="main-header">🔐 Encryption & Decryption App</h1>', unsafe_allow_html=True)
    
    # Sidebar for navigation
    st.sidebar.title("🛠️ Choose Encryption Type")
    encryption_type = st.sidebar.selectbox(
        "Select encryption method:",
        ["Symmetric Encryption", "Asymmetric Encryption (RSA)", "Hybrid Encryption"]
    )
    
    # Initialize session state for keys
    if 'rsa_keys' not in st.session_state:
        st.session_state.rsa_keys = None
    if 'hybrid_keys' not in st.session_state:
        st.session_state.hybrid_keys = None

    if encryption_type == "Symmetric Encryption":
        symmetric_encryption_ui()
    elif encryption_type == "Asymmetric Encryption (RSA)":
        asymmetric_encryption_ui()
    else:
        hybrid_encryption_ui()

if __name__ == "__main__":
    main()


