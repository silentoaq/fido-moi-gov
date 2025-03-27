import os
import jwt
import uuid
import hashlib
import base64
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Any, Optional
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from flask import current_app
from app.utils.crypto import (
    load_private_key, 
    load_public_key, 
    generate_salt, 
    base64url_encode, 
    base64url_decode,
    hash_data
)

logger = logging.getLogger(__name__)

def generate_disclosure(salt: str, key: str, value: Any) -> str:
    """
    生成披露對象
    
    Args:
        salt: 鹽值
        key: 聲明的鍵
        value: 聲明的值
    
    Returns:
        Base64url編碼的披露對象
    
    Raises:
        ValueError: 如果值無法序列化為JSON
    """
    try:
        # 確保值被正確序列化為JSON
        if isinstance(value, (dict, list, bool)) or value is None:
            value_str = json.dumps(value)
        else:
            value_str = json.dumps(value)
        
        # 創建披露對象字符串 (salt.key.value)
        disclosure = f"{salt}.{key}.{value_str}"
        
        # Base64url編碼
        return base64url_encode(disclosure.encode('utf-8'))
        
    except Exception as e:
        logger.error(f"生成披露對象錯誤: {str(e)}")
        raise ValueError(f"無法生成披露對象: {str(e)}")

def generate_sd_hash(disclosure: str) -> str:
    """
    生成選擇性披露哈希
    
    Args:
        disclosure: Base64url編碼的披露對象
    
    Returns:
        Base64url編碼的哈希
    
    Raises:
        ValueError: 如果披露對象無法解碼
    """
    try:
        # 解碼披露對象
        disclosure_bytes = base64url_decode(disclosure)
        
        # 計算SHA-256哈希
        digest = hashlib.sha256(disclosure_bytes).digest()
        
        # Base64url編碼
        return base64url_encode(digest)
        
    except Exception as e:
        logger.error(f"生成SD哈希錯誤: {str(e)}")
        raise ValueError(f"無法生成SD哈希: {str(e)}")

def generate_sd_jwt(
    issuer_did: str, 
    subject_did: str, 
    credential_id: str, 
    credential_data: Dict[str, Any], 
    issued_at: int, 
    expires_at: int
) -> str:
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
    
    Raises:
        ValueError: 如果生成過程中發生錯誤
    """
    try:
        # 驗證參數
        if not issuer_did or not subject_did or not credential_id:
            raise ValueError("Missing required parameters")
            
        if not credential_data:
            raise ValueError("Empty credential data")
            
        if issued_at >= expires_at:
            raise ValueError("Invalid time range: issued_at must be before expires_at")
        
        # 生成選擇性披露對象和哈希
        disclosures = []
        sd_digests = []
        
        for key, value in credential_data.items():
            # 為每個聲明生成唯一鹽值
            salt = generate_salt()
            
            # 生成披露對象
            disclosure = generate_disclosure(salt, key, value)
            
            # 計算披露哈希
            sd_digest = generate_sd_hash(disclosure)
            
            disclosures.append(disclosure)
            sd_digests.append(sd_digest)
        
        # 構建JWT頭部
        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": current_app.config.get('ISSUER_KID')
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
                    "id": f"https://fido.mov.gov/api/v1/credential-status/{credential_id}",
                    "type": "StatusList2021Entry"
                }
            },
            "_sd": sd_digests
        }
        
        # 加載私鑰
        private_key = load_private_key()
        
        # 簽名JWT
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
        
    except Exception as e:
        logger.error(f"生成SD-JWT憑證錯誤: {str(e)}")
        raise ValueError(f"無法生成SD-JWT憑證: {str(e)}")

def verify_sd_jwt(sd_jwt: str, expected_issuer: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """
    驗證SD-JWT格式的憑證
    
    Args:
        sd_jwt: SD-JWT格式的憑證字符串
        expected_issuer: 預期的發行者DID (可選)
    
    Returns:
        (是否有效, 錯誤消息, 解碼後的數據)
    """
    try:
        # 將SD-JWT拆分為JWT和選擇性披露部分
        parts = sd_jwt.split('~')
        if len(parts) < 1:
            return False, "Invalid SD-JWT format", {}
        
        jwt_part = parts[0]
        disclosures = parts[1:] if len(parts) > 1 else []
        
        # 解析JWT頭部
        try:
            header = jwt.get_unverified_header(jwt_part)
        except Exception as e:
            logger.error(f"解析JWT頭部錯誤: {str(e)}")
            return False, f"Error parsing JWT header: {str(e)}", {}
        
        # 獲取kid
        kid = header.get('kid')
        if not kid:
            return False, "Missing 'kid' in JWT header", {}
        
        # 加載公鑰
        try:
            public_key = load_public_key()
        except Exception as e:
            logger.error(f"加載公鑰錯誤: {str(e)}")
            return False, f"Error loading public key: {str(e)}", {}
        
        # 驗證JWT簽名
        try:
            decoded = jwt.decode(
                jwt_part,
                key=public_key,
                algorithms=["EdDSA"],
                audience=None  # 不檢查audience
            )
        except jwt.InvalidSignatureError:
            logger.warning("無效的JWT簽名")
            return False, "Invalid JWT signature", {}
        except jwt.ExpiredSignatureError:
            logger.warning("JWT已過期")
            return False, "JWT has expired", {}
        except jwt.InvalidTokenError as e:
            logger.warning(f"無效的JWT: {str(e)}")
            return False, f"Invalid JWT: {str(e)}", {}
        
        # 檢查發行者
        if expected_issuer and decoded.get('iss') != expected_issuer:
            logger.warning(f"發行者不匹配: {decoded.get('iss')} != {expected_issuer}")
            return False, f"Issuer mismatch: {decoded.get('iss')} != {expected_issuer}", {}
        
        # 檢查過期時間
        exp = decoded.get('exp')
        current_time = int(datetime.utcnow().timestamp())
        if exp and exp < current_time:
            logger.warning(f"憑證已過期: {datetime.fromtimestamp(exp).isoformat()}")
            return False, "Credential has expired", {}
        
        # 處理披露對象
        disclosed_claims = {}
        sd_digests = decoded.get('_sd', [])
        
        for disclosure in disclosures:
            try:
                # 計算披露對象的哈希
                sd_hash = generate_sd_hash(disclosure)
                
                # 檢查哈希是否存在於JWT的_sd數組中
                if sd_hash not in sd_digests:
                    logger.warning(f"披露哈希不在SD摘要中: {sd_hash}")
                    continue
                
                # 解碼披露對象
                disclosure_bytes = base64url_decode(disclosure)
                disclosure_str = disclosure_bytes.decode('utf-8')
                
                # 解析披露對象格式：salt.key.value
                parts = disclosure_str.split('.', 2)
                if len(parts) < 3:
                    logger.warning(f"無效的披露格式: {disclosure_str}")
                    continue
                
                salt, key, value_str = parts
                
                # 解析值（值應該是JSON格式）
                try:
                    value = json.loads(value_str)
                except json.JSONDecodeError:
                    logger.warning(f"披露值中的JSON無效: {value_str}")
                    value = value_str
                
                # 添加到披露聲明字典
                disclosed_claims[key] = value
                
            except Exception as e:
                logger.error(f"處理披露對象錯誤: {str(e)}")
                # 繼續處理其他披露對象
                continue
        
        # 合併JWT載荷與披露聲明
        result = {
            **decoded,
            "disclosed": disclosed_claims
        }
        
        return True, "", result
        
    except Exception as e:
        logger.error(f"SD-JWT驗證錯誤: {str(e)}")
        return False, str(e), {}

def create_credential_presentation(sd_jwt: str, disclosed_keys: List[str]) -> str:
    """
    創建SD-JWT憑證的選擇性披露演示
    
    Args:
        sd_jwt: 完整的SD-JWT憑證
        disclosed_keys: 要披露的聲明鍵列表
    
    Returns:
        選擇性披露的SD-JWT演示字符串
    
    Raises:
        ValueError: 如果SD-JWT格式無效
    """
    try:
        # 拆分SD-JWT
        parts = sd_jwt.split('~')
        if len(parts) < 1:
            raise ValueError("Invalid SD-JWT format")
        
        jwt_part = parts[0]
        all_disclosures = parts[1:] if len(parts) > 1 else []
        
        if not all_disclosures:
            # 如果沒有披露對象，直接返回JWT
            return jwt_part
        
        # 解析每個披露對象以獲取對應的鍵
        disclosure_map = {}
        for disclosure in all_disclosures:
            try:
                # 解碼披露對象
                disclosure_bytes = base64url_decode(disclosure)
                disclosure_str = disclosure_bytes.decode('utf-8')
                
                # 解析披露對象格式：salt.key.value
                parts = disclosure_str.split('.', 2)
                if len(parts) >= 3:
                    _, key, _ = parts
                    disclosure_map[key] = disclosure
            except Exception as e:
                logger.error(f"解析披露對象錯誤: {str(e)}")
                # 繼續處理其他披露對象
                continue
        
        # 根據指定的鍵選擇披露對象
        selected_disclosures = []
        for key in disclosed_keys:
            if key in disclosure_map:
                selected_disclosures.append(disclosure_map[key])
        
        # 構建選擇性披露的演示
        presentation = jwt_part
        for disclosure in selected_disclosures:
            presentation += f"~{disclosure}"
        
        return presentation
        
    except Exception as e:
        logger.error(f"創建憑證演示錯誤: {str(e)}")
        raise ValueError(f"無法創建憑證演示: {str(e)}")

def verify_credential_status(credential_id: str) -> Tuple[bool, Optional[str]]:
    """
    驗證憑證狀態
    
    Args:
        credential_id: 憑證ID
    
    Returns:
        (是否有效, 錯誤消息)
    """
    try:
        # 使用系統資料庫查詢憑證狀態
        from app import db
        from app.models import Credential
        
        credential = Credential.query.filter_by(credential_id=credential_id).first()
        
        if not credential:
            logger.warning(f"找不到憑證: {credential_id}")
            return False, "Credential not found"
        
        # 檢查憑證狀態
        if credential.status != 'valid':
            logger.warning(f"憑證狀態無效: {credential.status}")
            return False, f"Credential has been {credential.status}"
        
        # 檢查是否過期
        if credential.expires_at and credential.expires_at < datetime.utcnow():
            logger.warning(f"憑證已過期: {credential.expires_at.isoformat()}")
            return False, "Credential has expired"
        
        # 憑證有效
        return True, None
        
    except Exception as e:
        logger.error(f"驗證憑證狀態錯誤: {str(e)}")
        return False, f"Error verifying credential status: {str(e)}"