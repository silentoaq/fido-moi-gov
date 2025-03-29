import os
import json
import base64
import hashlib
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.backends import default_backend
from flask import current_app

def ensure_keys_exist():
    """確保系統擁有所需的密鑰對"""
    private_key_path = current_app.config['JWT_PRIVATE_KEY_PATH']
    public_key_path = current_app.config['JWT_PUBLIC_KEY_PATH']
    
    # 檢查密鑰文件是否存在
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        # 生成新的Ed25519密鑰對
        private_key = Ed25519PrivateKey.generate()
        
        # 序列化私鑰
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 序列化公鑰
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 確保目錄存在
        os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
        
        # 寫入文件
        with open(private_key_path, 'wb') as f:
            f.write(private_bytes)
        
        with open(public_key_path, 'wb') as f:
            f.write(public_bytes)
        
        current_app.logger.info("生成了新的密鑰對")

def get_private_key():
    """加載私鑰"""
    ensure_keys_exist()
    with open(current_app.config['JWT_PRIVATE_KEY_PATH'], 'rb') as f:
        private_bytes = f.read()
    
    private_key = serialization.load_pem_private_key(
        private_bytes,
        password=None,
        backend=default_backend()
    )
    
    return private_key

def get_public_key():
    """加載公鑰"""
    ensure_keys_exist()
    with open(current_app.config['JWT_PUBLIC_KEY_PATH'], 'rb') as f:
        public_bytes = f.read()
    
    public_key = serialization.load_pem_public_key(
        public_bytes,
        backend=default_backend()
    )
    
    return public_key

def get_public_key_jwk():
    """將公鑰轉換為JWK格式"""
    public_key = get_public_key()
    
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        # 處理EC密鑰
        numbers = public_key.public_numbers()
        x = numbers.x.to_bytes((numbers.curve.key_size + 7) // 8, byteorder='big')
        y = numbers.y.to_bytes((numbers.curve.key_size + 7) // 8, byteorder='big')
        
        return {
            "kty": "EC",
            "crv": "P-256" if numbers.curve.name == "secp256r1" else numbers.curve.name,
            "x": base64.urlsafe_b64encode(x).decode('ascii').rstrip('='),
            "y": base64.urlsafe_b64encode(y).decode('ascii').rstrip('='),
            "use": "sig",
            "alg": "ES256",
            "kid": "key-1"
        }
    elif hasattr(public_key, 'public_bytes_raw'):  # Ed25519PublicKey
        # 處理Ed25519密鑰
        key_bytes = public_key.public_bytes_raw()
        
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(key_bytes).decode('ascii').rstrip('='),
            "use": "sig", 
            "alg": "EdDSA",
            "kid": "key-1"
        }
    else:
        # 處理RSA密鑰
        numbers = public_key.public_numbers()
        
        return {
            "kty": "RSA",
            "n": base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('ascii').rstrip('='),
            "e": base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('ascii').rstrip('='),
            "use": "sig",
            "alg": "RS256",
            "kid": "key-1"
        }

def validate_did_proof(holder_did, proof):
    """驗證DID證明，特別是來自Phantom錢包的Solana簽名
    
    參數:
        holder_did (str): 持有者的DID，格式為did:pkh:solana:{address}
        proof (dict): 包含signature、created和domain等字段的證明對象
    
    返回:
        bool: 簽名驗證是否成功
    """
    import base64
    import nacl.signing
    import re
    from datetime import datetime, timezone
    
    # 檢查DID格式
    if not holder_did.startswith('did:pkh:solana:'):
        current_app.logger.error(f"Invalid DID format: {holder_did}")
        return False
    
    # 檢查是否提供了證明
    if not proof:
        current_app.logger.error("No proof provided")
        return False
    
    # 檢查證明類型
    if proof.get('type') != 'SolanaSigner2024':
        current_app.logger.error(f"Invalid proof type: {proof.get('type')}")
        return False
    
    # 從DID中提取Solana地址
    solana_address_match = re.match(r'did:pkh:solana:(.+)', holder_did)
    if not solana_address_match:
        current_app.logger.error(f"Could not extract Solana address from DID: {holder_did}")
        return False
    
    solana_address = solana_address_match.group(1)
    
    # 驗證Solana地址格式 (Base58, 32-44字符)
    if not re.match(r'^[1-9A-HJ-NP-Za-km-z]{32,44}$', solana_address):
        current_app.logger.error(f"Invalid Solana address format: {solana_address}")
        return False
    
    # 檢查時間戳是否在允許的範圍內
    try:
        created_time = proof.get('created')
        if not created_time:
            current_app.logger.error("Missing timestamp in proof")
            return False
        
        created_dt = datetime.strptime(created_time, '%Y-%m-%dT%H:%M:%SZ')
        created_dt = created_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        
        # 允許5分鐘的時間差
        time_diff = abs((now - created_dt).total_seconds())
        if time_diff > 300:  # 5分鐘
            current_app.logger.error(f"Timestamp too old: {time_diff} seconds")
            return False
    except Exception as e:
        current_app.logger.error(f"Error validating timestamp: {str(e)}")
        return False
    
    # 驗證domain是否與我們的主機匹配
    expected_domain = current_app.config.get('ISSUER_HOST')
    if proof.get('domain') != expected_domain:
        current_app.logger.error(f"Domain mismatch: {proof.get('domain')} vs {expected_domain}")
        return False
    
    # 實際的簽名驗證
    try:
        # 獲取簽名
        signature_base64 = proof.get('signature')
        if not signature_base64:
            current_app.logger.error("Missing signature in proof")
            return False
        
        # 解碼Base64簽名
        try:
            signature = base64.b64decode(signature_base64)
        except Exception as e:
            current_app.logger.error(f"Error decoding signature: {str(e)}")
            return False
        
        # 構造簽名的消息內容
        # Phantom錢包簽名的消息通常包含時間戳和域名
        message = f"Sign this message to prove you own the Solana address {solana_address}.\n\nDomain: {proof.get('domain')}\nTimestamp: {proof.get('created')}"
        
        # 構造驗證密鑰
        try:
            # Solana公鑰是Base58編碼的
            from base58 import b58decode
            public_key_bytes = b58decode(solana_address)
            verifier_key = nacl.signing.VerifyKey(public_key_bytes)
        except Exception as e:
            current_app.logger.error(f"Error constructing verifier key: {str(e)}")
            return False
        
        # 驗證簽名
        try:
            verifier_key.verify(message.encode('utf-8'), signature)
            current_app.logger.info(f"Signature verification successful for {holder_did}")
            return True
        except nacl.exceptions.BadSignatureError:
            current_app.logger.error("Signature verification failed: Bad signature")
            return False
        except Exception as e:
            current_app.logger.error(f"Signature verification failed: {str(e)}")
            return False
            
    except Exception as e:
        current_app.logger.error(f"Error during signature verification: {str(e)}")
        return False
        
    return False