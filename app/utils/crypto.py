import os
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from flask import current_app

def load_private_key():
    """載入Ed25519私鑰"""
    try:
        with open(current_app.config['PRIVATE_KEY_PATH'], 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        return private_key
    except Exception as e:
        current_app.logger.error(f"Failed to load private key: {str(e)}")
        raise

def load_public_key():
    """載入Ed25519公鑰"""
    try:
        with open(current_app.config['PUBLIC_KEY_PATH'], 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        return public_key
    except Exception as e:
        current_app.logger.error(f"Failed to load public key: {str(e)}")
        raise

def sign_message(message: bytes) -> bytes:
    """使用Ed25519私鑰簽名消息"""
    private_key = load_private_key()
    return private_key.sign(message)

def verify_signature(message: bytes, signature: bytes) -> bool:
    """使用Ed25519公鑰驗證簽名"""
    try:
        public_key = load_public_key()
        public_key.verify(signature, message)
        return True
    except Exception:
        return False

def get_public_key_jwk():
    """獲取公鑰的JWK格式"""
    public_key = load_public_key()
    
    # 獲取原始公鑰數據
    raw_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    # Base64url編碼
    x_value = base64.urlsafe_b64encode(raw_public_key).decode('utf-8').rstrip('=')
    
    # 返回JWK格式
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x_value,
        "kid": current_app.config.get('ISSUER_KID').split('#')[-1]
    }

def generate_random_id() -> str:
    """生成隨機ID"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')

def generate_salt() -> str:
    """生成隨機鹽值"""
    return base64.urlsafe_b64encode(os.urandom(8)).decode('utf-8').rstrip('=')

def hash_data(data: bytes) -> bytes:
    """使用SHA-256哈希數據"""
    return hashlib.sha256(data).digest()

def base64url_encode(data: bytes) -> str:
    """Base64url編碼"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def base64url_decode(data: str) -> bytes:
    """Base64url解碼"""
    # 處理填充
    padding = '=' * (4 - (len(data) % 4))
    padded_data = data + padding
    return base64.urlsafe_b64decode(padded_data.encode('utf-8'))