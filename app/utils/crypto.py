import os
import base64
import hashlib
import logging
from typing import Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from flask import current_app

logger = logging.getLogger(__name__)

def load_private_key():
    """
    載入Ed25519私鑰
    
    Returns:
        Ed25519PrivateKey 實例
    
    Raises:
        IOError: 如果無法讀取密鑰文件
        ValueError: 如果密鑰格式無效
    """
    try:
        key_path = current_app.config['PRIVATE_KEY_PATH']
        
        if not os.path.exists(key_path):
            raise IOError(f"Private key file not found at {key_path}")
            
        with open(key_path, 'rb') as key_file:
            private_key_data = key_file.read()
            
        try:
            private_key = serialization.load_pem_private_key(
                private_key_data,
                password=None
            )
            
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("Loaded key is not an Ed25519PrivateKey")
                
            return private_key
            
        except Exception as e:
            logger.error(f"Failed to deserialize private key: {str(e)}")
            raise ValueError(f"Invalid private key format: {str(e)}")
            
    except Exception as e:
        logger.error(f"Failed to load private key: {str(e)}")
        raise

def load_public_key():
    """
    載入Ed25519公鑰
    
    Returns:
        Ed25519PublicKey 實例
    
    Raises:
        IOError: 如果無法讀取密鑰文件
        ValueError: 如果密鑰格式無效
    """
    try:
        key_path = current_app.config['PUBLIC_KEY_PATH']
        
        if not os.path.exists(key_path):
            raise IOError(f"Public key file not found at {key_path}")
            
        with open(key_path, 'rb') as key_file:
            public_key_data = key_file.read()
            
        try:
            public_key = serialization.load_pem_public_key(
                public_key_data
            )
            
            if not isinstance(public_key, Ed25519PublicKey):
                raise ValueError("Loaded key is not an Ed25519PublicKey")
                
            return public_key
            
        except Exception as e:
            logger.error(f"Failed to deserialize public key: {str(e)}")
            raise ValueError(f"Invalid public key format: {str(e)}")
            
    except Exception as e:
        logger.error(f"Failed to load public key: {str(e)}")
        raise

def sign_message(message: bytes, private_key: Optional[Ed25519PrivateKey] = None) -> bytes:
    """
    使用Ed25519私鑰簽名消息
    
    Args:
        message: 要簽名的消息字節
        private_key: 可選的私鑰，如果未提供則使用load_private_key加載
    
    Returns:
        簽名字節
    
    Raises:
        ValueError: 如果無法加載私鑰或簽名失敗
    """
    try:
        if private_key is None:
            private_key = load_private_key()
            
        signature = private_key.sign(message)
        return signature
        
    except Exception as e:
        logger.error(f"Failed to sign message: {str(e)}")
        raise ValueError(f"Failed to sign message: {str(e)}")

def verify_signature(message: bytes, signature: bytes, public_key: Optional[Ed25519PublicKey] = None) -> bool:
    """
    使用Ed25519公鑰驗證簽名
    
    Args:
        message: 原始消息字節
        signature: 簽名字節
        public_key: 可選的公鑰，如果未提供則使用load_public_key加載
    
    Returns:
        簽名是否有效
    """
    try:
        if public_key is None:
            public_key = load_public_key()
            
        public_key.verify(signature, message)
        return True
        
    except InvalidSignature:
        logger.warning("Signature verification failed: Invalid signature")
        return False
        
    except Exception as e:
        logger.error(f"Signature verification error: {str(e)}")
        return False

def get_public_key_jwk():
    """
    獲取公鑰的JWK格式
    
    Returns:
        JWK格式的公鑰字典
    
    Raises:
        ValueError: 如果無法加載公鑰或轉換格式
    """
    try:
        public_key = load_public_key()
        
        # 獲取原始公鑰數據
        raw_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Base64url編碼
        x_value = base64.urlsafe_b64encode(raw_public_key).decode('utf-8').rstrip('=')
        
        # 從配置獲取kid
        kid = current_app.config.get('ISSUER_KID').split('#')[-1]
        
        # 返回JWK格式
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_value,
            "kid": kid
        }
        
    except Exception as e:
        logger.error(f"Failed to create JWK: {str(e)}")
        raise ValueError(f"Failed to create JWK: {str(e)}")

def generate_random_bytes(length: int = 16) -> bytes:
    """
    生成加密安全的隨機字節
    
    Args:
        length: 字節長度
    
    Returns:
        隨機字節
    """
    return os.urandom(length)

def generate_random_id() -> str:
    """
    生成隨機ID (URL安全的Base64編碼)
    
    Returns:
        Base64url編碼的隨機ID
    """
    random_bytes = generate_random_bytes(16)
    return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')

def generate_salt() -> str:
    """
    生成隨機鹽值 (URL安全的Base64編碼)
    
    Returns:
        Base64url編碼的鹽值
    """
    random_bytes = generate_random_bytes(8)
    return base64.urlsafe_b64encode(random_bytes).decode('utf-8').rstrip('=')

def hash_data(data: bytes) -> bytes:
    """
    使用SHA-256哈希數據
    
    Args:
        data: 要哈希的數據
    
    Returns:
        哈希結果
    """
    return hashlib.sha256(data).digest()

def base64url_encode(data: bytes) -> str:
    """
    Base64url編碼
    
    Args:
        data: 要編碼的字節
    
    Returns:
        URL安全的Base64編碼字符串，不帶填充
    """
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def base64url_decode(data: str) -> bytes:
    """
    Base64url解碼
    
    Args:
        data: 要解碼的Base64url字符串
    
    Returns:
        解碼後的字節
    
    Raises:
        ValueError: 如果輸入不是有效的Base64編碼
    """
    try:
        # 處理填充
        padding_needed = 4 - (len(data) % 4)
        if padding_needed < 4:
            padded_data = data + ('=' * padding_needed)
        else:
            padded_data = data
            
        return base64.urlsafe_b64decode(padded_data.encode('utf-8'))
        
    except Exception as e:
        logger.error(f"Base64url decode error: {str(e)}")
        raise ValueError(f"Invalid Base64url encoding: {str(e)}")

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    執行時間固定的比較，防止定時攻擊
    
    Args:
        a, b: 要比較的字節
    
    Returns:
        兩個值是否相等
    """
    if len(a) != len(b):
        return False
        
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
        
    return result == 0