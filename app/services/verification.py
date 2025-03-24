from typing import Dict, Tuple, Any, Optional
from datetime import datetime
from flask import current_app
from app import db
from app.models import Credential
from app.utils.sd_jwt import verify_sd_jwt, parse_sd_jwt

def verify_credential(sd_jwt: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    驗證憑證的有效性
    
    Args:
        sd_jwt: SD-JWT格式的憑證
    
    Returns:
        (是否有效, 錯誤消息, 憑證數據)
    """
    # 使用SD-JWT工具進行密碼學驗證
    is_valid, error_msg, payload = verify_sd_jwt(
        sd_jwt, 
        expected_issuer=current_app.config.get('ISSUER_DID')
    )
    
    if not is_valid:
        return False, error_msg, {}
    
    # 檢查憑證ID
    credential_id = payload.get('jti')
    if not credential_id:
        return False, "憑證缺少ID (jti)", {}
    
    # 檢查數據庫中憑證的狀態
    credential = Credential.query.filter_by(credential_id=credential_id).first()
    if not credential:
        return False, "憑證不存在於系統中", {}
    
    if credential.status != 'valid':
        return False, f"憑證已{credential.status}", {}
    
    # 檢查過期時間
    if credential.expires_at and credential.expires_at < datetime.utcnow():
        return False, "憑證已過期", {}
    
    # 獲取完整的披露聲明
    try:
        _, disclosed_claims = parse_sd_jwt(sd_jwt)
        
        # 合併載荷和披露聲明
        result = {
            "credential_id": credential_id,
            "issuer": payload.get('iss'),
            "subject": payload.get('sub'),
            "issued_at": datetime.fromtimestamp(payload.get('iat', 0)).isoformat() if payload.get('iat') else None,
            "expires_at": datetime.fromtimestamp(payload.get('exp', 0)).isoformat() if payload.get('exp') else None,
            "credential_type": payload.get('vc', {}).get('type', []),
            "disclosed_claims": disclosed_claims
        }
        
        return True, "", result
    
    except Exception as e:
        current_app.logger.error(f"解析憑證失敗: {str(e)}")
        return False, f"解析憑證失敗: {str(e)}", {}

def check_credential_status(credential_id: str) -> Tuple[bool, Optional[str], Dict[str, Any]]:
    """
    檢查憑證的狀態
    
    Args:
        credential_id: 憑證ID
    
    Returns:
        (是否有效, 錯誤消息, 狀態數據)
    """
    credential = Credential.query.filter_by(credential_id=credential_id).first()
    
    if not credential:
        return False, "憑證不存在", {}
    
    # 檢查憑證狀態
    is_valid = credential.status == 'valid'
    reason = None if is_valid else "憑證已撤銷"
    
    # 檢查過期時間
    if is_valid and credential.expires_at and credential.expires_at < datetime.utcnow():
        is_valid = False
        reason = "憑證已過期"
    
    # 構建狀態數據
    status_data = {
        "credential_id": credential_id,
        "status": credential.status,
        "issued_at": credential.issued_at.isoformat() if credential.issued_at else None,
        "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
        "revoked_at": credential.revoked_at.isoformat() if credential.revoked_at else None
    }
    
    return is_valid, reason, status_data

def validate_credential_claims(disclosed_claims: Dict[str, Any], required_claims: Dict[str, Any]) -> Tuple[bool, str]:
    """
    驗證披露的聲明是否滿足要求
    
    Args:
        disclosed_claims: 披露的聲明
        required_claims: 要求的聲明及其值
    
    Returns:
        (是否有效, 錯誤消息)
    """
    for key, required_value in required_claims.items():
        # 檢查是否存在
        if key not in disclosed_claims:
            return False, f"缺少必需的聲明: {key}"
        
        # 檢查值是否匹配（如果需要）
        if required_value is not None and disclosed_claims[key] != required_value:
            return False, f"聲明 {key} 的值不匹配"
    
    return True, ""