import jwt
import json
import time
import uuid
import base64
import hashlib
import os
from datetime import datetime, timedelta
from flask import current_app
from app.utils.crypto import get_private_key, get_public_key
from app.models.credential import PreAuthCode, AccessToken
from app import db

def generate_pre_auth_code(application_id=None):
    """生成預授權碼"""
    # 生成隨機字串作為預授權碼
    code = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
    # 設置過期時間
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    return code, expires_at

def validate_pre_auth_code(code):
    """驗證預授權碼"""
    pre_auth = PreAuthCode.query.filter_by(code=code).first()
    
    if not pre_auth:
        return None
    
    # 檢查是否過期
    if pre_auth.expires_at < datetime.utcnow():
        return None
    
    # 檢查是否被使用過
    if pre_auth.is_used:
        return None
    
    return pre_auth

def generate_access_token(pre_auth_code):
    """生成訪問令牌"""
    # 生成JWT格式的訪問令牌
    expires_at = datetime.utcnow() + current_app.config['ACCESS_TOKEN_EXPIRES']
    
    payload = {
        'iss': f"did:web:{current_app.config['ISSUER_HOST']}",
        'sub': pre_auth_code,
        'iat': datetime.utcnow(),
        'exp': expires_at,
        'jti': str(uuid.uuid4()),
        'pre_auth_code': pre_auth_code
    }
    
    # 使用私鑰簽名
    token = jwt.encode(
        payload,
        get_private_key(),
        algorithm='EdDSA'
    )
    
    return token, expires_at

def validate_access_token(token):
    """驗證訪問令牌"""
    try:
        # 從數據庫查詢令牌
        access_token = AccessToken.query.filter_by(token=token).first()
        
        if not access_token:
            return None
        
        # 檢查是否過期
        if access_token.expires_at < datetime.utcnow():
            return None
        
        # 驗證JWT簽名
        payload = jwt.decode(
            token,
            get_public_key(),
            algorithms=['EdDSA'],
            options={'verify_signature': True}
        )
        
        return {
            'pre_auth_code': payload['pre_auth_code'],
            'jti': payload['jti']
        }
    except Exception as e:
        current_app.logger.error(f"令牌驗證失敗: {str(e)}")
        return None

def generate_c_nonce():
    """生成用於憑證請求的nonce"""
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')

def create_disclosure(key, value):
    """創建SD-JWT中的披露對象"""
    # 生成隨機salt (32位隨機字節)
    salt = base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')
    
    # 構建披露對象 [salt, key, value]
    disclosure = [salt, key, value]
    
    # 將披露對象序列化為JSON並計算其SHA-256雜湊
    disclosure_json = json.dumps(disclosure, ensure_ascii=False)
    digest = hashlib.sha256(disclosure_json.encode('utf-8')).digest()
    digest_b64 = base64.urlsafe_b64encode(digest).decode().rstrip('=')
    
    return {
        "hash": digest_b64,
        "disclosure": disclosure_json,
        "disclosure_b64": base64.urlsafe_b64encode(disclosure_json.encode('utf-8')).decode()
    }

def generate_credential(holder_did, name, birth_date, national_id):
    """生成SD-JWT格式的可驗證憑證"""
    # 生成憑證ID
    credential_id = str(uuid.uuid4())
    
    # 為每個屬性生成披露對象
    name_disclosure = create_disclosure("name", name)
    birth_date_disclosure = create_disclosure("birthDate", birth_date)
    national_id_disclosure = create_disclosure("nationalId", national_id)
    
    # 構建JWT主體
    current_time = int(time.time())
    jwt_payload = {
        "iss": f"did:web:{current_app.config['ISSUER_HOST']}",
        "sub": holder_did,
        "iat": current_time,
        "exp": current_time + 31536000,  # 一年有效期
        "jti": credential_id,
        "vc": {
            "type": ["VerifiableCredential", "TaiwanNaturalPersonCredential"],
            "credentialSubject": {
                "_sd": [
                    name_disclosure["hash"],
                    birth_date_disclosure["hash"],
                    national_id_disclosure["hash"]
                ]
            }
        }
    }
    
    # 使用Issuer私鑰簽名JWT
    private_key = get_private_key()
    
    # 如果是EdDSA私鑰，使用適當的算法
    if hasattr(private_key, 'sign'):  # Ed25519PrivateKey
        jwt_header = {"alg": "EdDSA", "typ": "JWT"}
        jwt_token = jwt.encode(jwt_payload, private_key, algorithm="EdDSA", headers=jwt_header)
    else:
        # 不支持的密鑰類型
        current_app.logger.error("不支持的私鑰類型，無法生成JWT")
        return None
    
    # 構建完整的SD-JWT (JWT + 披露對象)
    sd_jwt = jwt_token
    sd_jwt += "~" + name_disclosure["disclosure_b64"]
    sd_jwt += "~" + birth_date_disclosure["disclosure_b64"]
    sd_jwt += "~" + national_id_disclosure["disclosure_b64"]
    
    # 返回SD-JWT和披露信息
    return {
        "credential_id": credential_id,
        "sd_jwt": sd_jwt,
        "disclosures": {
            "name": json.loads(name_disclosure["disclosure"]),
            "birthDate": json.loads(birth_date_disclosure["disclosure"]),
            "nationalId": json.loads(national_id_disclosure["disclosure"])
        }
    }   