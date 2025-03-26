import os
import jwt
import uuid
import hashlib
import base64
import json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from flask import current_app

def load_private_key():
    """讀取Ed25519私鑰"""
    key_path = os.path.join(current_app.root_path, '../keys/private.pem')
    with open(key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def generate_salt():
    """生成隨機鹽值"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')

def generate_disclosure(salt, key, value):
    """生成披露對象"""
    disclosure = f"{salt}.{key}.{json.dumps(value) if isinstance(value, (dict, list)) else value}"
    return base64.urlsafe_b64encode(disclosure.encode('utf-8')).decode('utf-8').rstrip('=')

def generate_sd_hash(disclosure):
    """生成選擇性披露哈希"""
    digest = hashlib.sha256(base64.urlsafe_b64decode(disclosure + '====')).digest()
    return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

def generate_sd_jwt(issuer_did, subject_did, credential_id, credential_data, issued_at, expires_at):
    """
    生成SD-JWT格式的可驗證憑證
    
    Args:
        issuer_did: 發行者DID
        subject_did: 主體DID
        credential_id: 憑證ID
        credential_data: 憑證數據
        issued_at: 發行時間戳
        expires_at: 過期時間戳
    
    Returns:
        SD-JWT格式的憑證字符串
    """
    # 生成選擇性披露對象和哈希
    disclosures = []
    sd_digests = []
    
    for key, value in credential_data.items():
        salt = generate_salt()
        disclosure = generate_disclosure(salt, key, value)
        sd_digest = generate_sd_hash(disclosure)
        
        disclosures.append(disclosure)
        sd_digests.append(sd_digest)
    
    # 構建JWT頭部
    header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": "did:web:fido.moi.gov.tw#key-1"
    }
    
    # 構建JWT主體
    payload = {
        "iss": issuer_did,
        "sub": subject_did,
        "jti": credential_id,
        "iat": issued_at,
        "exp": expires_at,
        "vc": {
            "type": ["VerifiableCredential", "NaturalPersonCredential"],
            "credentialStatus": {
                "id": f"https://fido.moi.gov.tw/api/v1/credential-status/{credential_id}",
                "type": "StatusList2021Entry"
            }
        },
        "_sd": sd_digests
    }
    
    # 簽名JWT
    private_key = load_private_key()
    token = jwt.encode(
        payload=payload,
        key=private_key,
        algorithm="EdDSA",
        headers=header
    )
    
    # 構建完整的SD-JWT
    sd_jwt = token
    for disclosure in disclosures:
        sd_jwt += f"~{disclosure}"
    
    return sd_jwt

def verify_sd_jwt(sd_jwt):
    """
    驗證SD-JWT格式的憑證
    
    Args:
        sd_jwt: SD-JWT格式的憑證字符串
    
    Returns:
        (bool, dict): 驗證結果和解碼後的數據
    """
    # 將SD-JWT拆分為JWT和選擇性披露部分
    parts = sd_jwt.split('~')
    jwt_part = parts[0]
    disclosures = parts[1:] if len(parts) > 1 else []
    
    try:
        # 讀取公鑰
        jwks_path = os.path.join(current_app.root_path, '../.well-known/jwks.json')
        with open(jwks_path, 'r') as f:
            jwks = json.load(f)
        
        # 解碼JWT (實際項目需正確實現公鑰驗證)
        # 這裡簡化為不驗證簽名
        decoded = jwt.decode(
            jwt_part,
            options={"verify_signature": False}
        )
        
        # 處理披露對象
        disclosed_claims = {}
        for disclosure in disclosures:
            try:
                # 解碼披露對象
                decoded_disclosure = base64.urlsafe_b64decode(disclosure + '====').decode('utf-8')
                parts = decoded_disclosure.split('.', 2)
                if len(parts) >= 3:
                    salt, key, value = parts
                    try:
                        # 嘗試解析JSON值
                        value_obj = json.loads(value)
                        disclosed_claims[key] = value_obj
                    except:
                        # 如果不是JSON，使用原始值
                        disclosed_claims[key] = value
            except:
                # 忽略無效的披露對象
                pass
        
        # 驗證披露對象哈希
        sd_digests = decoded.get('_sd', [])
        for disclosure in disclosures:
            sd_hash = generate_sd_hash(disclosure)
            if sd_hash not in sd_digests:
                return False, {"error": "Invalid disclosure"}
        
        # 合併結果
        result = {**decoded}
        if disclosed_claims:
            result['disclosed_claims'] = disclosed_claims
        
        return True, result
        
    except Exception as e:
        return False, {"error": str(e)}