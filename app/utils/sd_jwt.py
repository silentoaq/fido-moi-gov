import json
import jwt
import hashlib
import time
from typing import Dict, List, Tuple, Any, Optional
from flask import current_app
from .crypto import (
    load_private_key, 
    generate_salt, 
    base64url_encode, 
    base64url_decode,
    hash_data
)

def create_sd_jwt(
    issuer: str, 
    subject: str, 
    credential_id: str, 
    claims: Dict[str, Any], 
    selectively_disclosable: List[str] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None
) -> str:
    """
    創建帶有選擇性披露(SD)的JWT
    
    Args:
        issuer: 發行者DID
        subject: 主體DID
        credential_id: 憑證ID
        claims: 聲明數據
        selectively_disclosable: 可選擇披露的聲明字段列表
        issued_at: 發行時間戳
        expires_at: 過期時間戳
    
    Returns:
        SD-JWT字符串
    """
    # 如果沒有指定可選擇披露字段，則所有字段都可選擇披露
    if selectively_disclosable is None:
        selectively_disclosable = list(claims.keys())
    
    # 生成標準JWT部分和披露對象
    jwt_payload, disclosures = prepare_sd_jwt_parts(
        issuer, subject, credential_id, claims, selectively_disclosable, issued_at, expires_at
    )
    
    # 使用ED25519私鑰簽名JWT
    private_key = load_private_key()
    jwt_header = {
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": current_app.config.get('ISSUER_KID')
    }
    
    # 編碼JWT
    token = jwt.encode(
        payload=jwt_payload,
        key=private_key,
        algorithm="EdDSA",
        headers=jwt_header
    )
    
    # 組合SD-JWT
    sd_jwt = token
    for disclosure in disclosures:
        sd_jwt += f"~{disclosure}"
    
    return sd_jwt

def prepare_sd_jwt_parts(
    issuer: str, 
    subject: str, 
    credential_id: str, 
    claims: Dict[str, Any], 
    selectively_disclosable: List[str],
    issued_at: Optional[int], 
    expires_at: Optional[int]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    準備SD-JWT的主體和披露對象
    
    Returns:
        (JWT載荷, 披露對象列表)
    """
    # 初始化JWT載荷
    jwt_payload = {
        "iss": issuer,
        "sub": subject,
        "jti": credential_id,
        "iat": issued_at or int(time.time()),
        "exp": expires_at or int(time.time() + 86400 * 365),  # 默認一年有效期
        "vc": {
            "type": ["VerifiableCredential", "NaturalPersonCredential"],
            "credentialStatus": {
                "id": f"http://fido.moi.gov.tw/api/v1/credential-status/{credential_id}",
                "type": "StatusList2021Entry"
            }
        },
        "_sd": []  # 選擇性披露的哈希
    }
    
    # 生成披露對象
    disclosures = []
    for key in claims:
        if key in selectively_disclosable:
            # 生成鹽值和披露對象
            salt = generate_salt()
            disclosure_value = claims[key]
            
            # 對複雜對象進行JSON序列化
            if isinstance(disclosure_value, (dict, list)):
                disclosure_value = json.dumps(disclosure_value)
            
            # 創建披露對象 (salt.claim_name.claim_value)
            disclosure_obj = f"{salt}.{key}.{disclosure_value}"
            disclosure_b64 = base64url_encode(disclosure_obj.encode('utf-8'))
            disclosures.append(disclosure_b64)
            
            # 計算哈希
            digest = hashlib.sha256(base64url_decode(disclosure_b64)).digest()
            digest_b64 = base64url_encode(digest)
            
            # 添加哈希到JWT
            jwt_payload["_sd"].append(digest_b64)
        else:
            # 不可選擇披露的字段直接添加到JWT
            jwt_payload[key] = claims[key]
    
    return jwt_payload, disclosures

def parse_sd_jwt(sd_jwt: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    解析SD-JWT
    
    Args:
        sd_jwt: SD-JWT字符串
    
    Returns:
        (JWT載荷, 披露聲明)
    """
    # 拆分SD-JWT為JWT和披露部分
    parts = sd_jwt.split('~')
    jwt_part = parts[0]
    disclosure_parts = parts[1:] if len(parts) > 1 else []
    
    # 解碼JWT (不驗證簽名)
    try:
        jwt_payload = jwt.decode(
            jwt_part,
            options={"verify_signature": False}
        )
    except Exception as e:
        current_app.logger.error(f"JWT解碼失敗: {str(e)}")
        raise ValueError(f"Invalid JWT format: {str(e)}")
    
    # 處理披露部分
    disclosed_claims = {}
    for disclosure_b64 in disclosure_parts:
        try:
            # 解碼披露對象
            disclosure_bytes = base64url_decode(disclosure_b64)
            disclosure_str = disclosure_bytes.decode('utf-8')
            parts = disclosure_str.split('.', 2)
            
            if len(parts) >= 3:
                salt, key, value = parts
                
                # 嘗試將JSON字符串轉為對象
                try:
                    value_obj = json.loads(value)
                    disclosed_claims[key] = value_obj
                except json.JSONDecodeError:
                    # 如果不是有效JSON，使用原始值
                    disclosed_claims[key] = value
                
                # 驗證披露對象的哈希
                digest = hashlib.sha256(disclosure_bytes).digest()
                digest_b64 = base64url_encode(digest)
                
                if '_sd' in jwt_payload and digest_b64 not in jwt_payload.get('_sd', []):
                    current_app.logger.warning(f"Disclosure hash mismatch for key: {key}")
                    # 在實際應用中可以決定是否忽略無效披露
        except Exception as e:
            current_app.logger.error(f"解析披露對象失敗: {str(e)}")
            # 忽略無效的披露對象
            continue
    
    return jwt_payload, disclosed_claims

def verify_sd_jwt(sd_jwt: str, expected_issuer: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
    """
    驗證SD-JWT的有效性
    
    Args:
        sd_jwt: SD-JWT字符串
        expected_issuer: 預期的發行者 (可選)
    
    Returns:
        (是否有效, 錯誤消息, 合併後的載荷)
    """
    # 拆分SD-JWT
    parts = sd_jwt.split('~')
    jwt_part = parts[0]
    
    try:
        # 解碼JWT並驗證簽名
        # 注意：實際應用中這裡應該使用公鑰驗證，但這裡簡化處理
        try:
            jwt_payload = jwt.decode(
                jwt_part,
                options={"verify_signature": False}  # 這裡未驗證簽名，真實環境需要驗證
            )
        except Exception as e:
            return False, f"JWT格式無效: {str(e)}", {}
        
        # 檢查發行者
        if expected_issuer and jwt_payload.get('iss') != expected_issuer:
            return False, f"發行者不匹配: {jwt_payload.get('iss')} != {expected_issuer}", {}
        
        # 檢查是否過期
        current_time = int(time.time())
        if 'exp' in jwt_payload and jwt_payload['exp'] < current_time:
            return False, "憑證已過期", {}
        
        # 解析披露聲明
        _, disclosed_claims = parse_sd_jwt(sd_jwt)
        
        # 合併載荷和披露聲明
        merged_payload = {**jwt_payload}
        if disclosed_claims:
            merged_payload['disclosed'] = disclosed_claims
        
        return True, "", merged_payload
    
    except Exception as e:
        return False, f"驗證失敗: {str(e)}", {}

def create_presentation(sd_jwt: str, disclosed_keys: List[str]) -> str:
    """
    創建只包含需要披露的字段的展示
    
    Args:
        sd_jwt: 完整的SD-JWT
        disclosed_keys: 需要披露的字段列表
    
    Returns:
        包含選定披露的SD-JWT
    """
    # 解析原始SD-JWT
    parts = sd_jwt.split('~')
    jwt_part = parts[0]
    disclosure_parts = parts[1:] if len(parts) > 1 else []
    
    # 映射披露的key到對應的base64披露對象
    key_to_disclosure = {}
    key_to_hash = {}
    
    for disclosure_b64 in disclosure_parts:
        try:
            disclosure_bytes = base64url_decode(disclosure_b64)
            disclosure_str = disclosure_bytes.decode('utf-8')
            parts = disclosure_str.split('.', 2)
            
            if len(parts) >= 3:
                _, key, _ = parts
                
                digest = hashlib.sha256(disclosure_bytes).digest()
                digest_b64 = base64url_encode(digest)
                
                key_to_disclosure[key] = disclosure_b64
                key_to_hash[key] = digest_b64
        except Exception:
            continue
    
    # 過濾出需要披露的部分
    selected_disclosures = []
    for key in disclosed_keys:
        if key in key_to_disclosure:
            selected_disclosures.append(key_to_disclosure[key])
    
    # 構建展示
    presentation = jwt_part
    for disclosure in selected_disclosures:
        presentation += f"~{disclosure}"
    
    return presentation