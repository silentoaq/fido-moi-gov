import json
import uuid
import base64
import requests
from datetime import datetime
from typing import Dict, Any, Optional, Tuple, List
from flask import current_app
from app import db
from app.models import Application, Credential
from app.utils.crypto import sign_message, verify_signature, load_private_key, load_public_key
from app.services.credential import generate_sd_jwt

# DIDComm消息類型
MESSAGE_TYPES = {
    # 認證消息
    'DID_AUTH_REQUEST': 'https://didcomm.org/did-auth/1.0/request',
    'DID_AUTH_RESPONSE': 'https://didcomm.org/did-auth/1.0/response',
    
    # 申請數據消息
    'APPLICATION_DATA_REQUEST': 'https://didcomm.org/application/1.0/data-request',
    'APPLICATION_DATA_RESPONSE': 'https://didcomm.org/application/1.0/data-response',
    
    # 憑證消息
    'CREDENTIAL_OFFER': 'https://didcomm.org/issue-credential/1.0/offer',
    'CREDENTIAL_REQUEST': 'https://didcomm.org/issue-credential/1.0/request',
    'CREDENTIAL_ISSUE': 'https://didcomm.org/issue-credential/1.0/issue',
    
    # 憑證驗證消息
    'PRESENTATION_REQUEST': 'https://didcomm.org/present-proof/1.0/request',
    'PRESENTATION': 'https://didcomm.org/present-proof/1.0/presentation',
    'VERIFICATION_RESULT': 'https://didcomm.org/present-proof/1.0/verification-result',
    
    # 問題報告
    'PROBLEM_REPORT': 'https://didcomm.org/report-problem/1.0/problem-report'
}

def process_didcomm_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    處理接收到的DIDComm消息
    
    Args:
        message: DIDComm消息
        
    Returns:
        回應消息
    """
    try:
        # 檢查基本消息結構
        if not isinstance(message, dict):
            raise ValueError("Invalid message format: expected JSON object")
        
        required_fields = ['type', 'id']
        for field in required_fields:
            if field not in message:
                raise ValueError(f"Missing required field: {field}")
        
        message_type = message.get('type')
        message_id = message.get('id')
        
        # 如果消息有簽名，驗證簽名
        signature = message.get('signature')
        from_did = message.get('from')
        
        if signature and from_did:
            is_valid = verify_didcomm_signature(message, signature, from_did)
            if not is_valid:
                return create_problem_report(
                    message_id,
                    current_app.config.get('ISSUER_DID'),
                    from_did,
                    "Invalid message signature"
                )
        
        # 根據消息類型進行處理
        if message_type == MESSAGE_TYPES['DID_AUTH_REQUEST']:
            return process_did_auth_request(message)
        
        elif message_type == MESSAGE_TYPES['DID_AUTH_RESPONSE']:
            return process_did_auth_response(message)
        
        elif message_type == MESSAGE_TYPES['APPLICATION_DATA_RESPONSE']:
            return process_application_data(message)
        
        elif message_type == MESSAGE_TYPES['CREDENTIAL_REQUEST']:
            return process_credential_request(message)
        
        elif message_type == MESSAGE_TYPES['PRESENTATION']:
            return process_presentation(message)
        
        else:
            return create_problem_report(
                message_id,
                current_app.config.get('ISSUER_DID'),
                from_did,
                f"Unsupported message type: {message_type}"
            )
            
    except Exception as e:
        current_app.logger.error(f"DIDComm處理錯誤: {str(e)}")
        return create_problem_report(
            message.get('id', str(uuid.uuid4())),
            current_app.config.get('ISSUER_DID'),
            message.get('from'),
            f"Error processing message: {str(e)}"
        )

def fetch_did_document(did: str) -> Dict[str, Any]:
    """
    獲取DID文檔
    
    Args:
        did: DID字符串，例如 did:pkh:solana:123456
    
    Returns:
        DID文檔
    
    Raises:
        ValueError: 如果DID格式不正確或無法解析
    """
    if did.startswith('did:web:'):
        # Web DID解析
        domain = did[9:]  # 移除 "did:web:"
        url = f"https://{domain}/.well-known/did.json"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            current_app.logger.error(f"獲取Web DID文檔錯誤: {str(e)}")
            raise ValueError(f"無法獲取DID文檔: {str(e)}")
            
    elif did.startswith('did:pkh:solana:'):
        # Solana PKH DID解析
        address = did[16:]  # 移除 "did:pkh:solana:"
        
        # 為Solana PKH DID構建標準DID文檔
        did_doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [
                {
                    "id": f"{did}#controller",
                    "type": "Ed25519VerificationKey2018",
                    "controller": did,
                    "publicKeyBase58": address
                }
            ],
            "authentication": [f"{did}#controller"],
            "assertionMethod": [f"{did}#controller"]
        }
        return did_doc
    else:
        raise ValueError(f"不支持的DID方法: {did}")

def get_verification_method(did_document: Dict[str, Any], kid: str = None) -> Dict[str, Any]:
    """
    從DID文檔中獲取驗證方法
    
    Args:
        did_document: DID文檔
        kid: 密鑰ID (可選)
    
    Returns:
        驗證方法信息
    
    Raises:
        ValueError: 如果找不到驗證方法
    """
    verification_methods = did_document.get('verificationMethod', [])
    
    if not verification_methods:
        raise ValueError("DID文檔中沒有驗證方法")
    
    if kid:
        # 根據kid查找特定的驗證方法
        for method in verification_methods:
            if method.get('id') == kid:
                return method
        
        # 如果找不到完全匹配，嘗試部分匹配
        for method in verification_methods:
            if kid in method.get('id', ''):
                return method
                
        raise ValueError(f"在DID文檔中找不到指定的密鑰ID: {kid}")
    else:
        # 返回第一個驗證方法
        return verification_methods[0]

def verify_didcomm_signature(message: Dict[str, Any], signature: str, from_did: str) -> bool:
    """
    驗證DIDComm消息的簽名
    
    Args:
        message: DIDComm消息
        signature: Base64編碼的簽名
        from_did: 發送者的DID
    
    Returns:
        簽名是否有效
    """
    try:
        # 創建要驗證的消息副本，移除簽名字段
        message_copy = message.copy()
        message_copy.pop('signature', None)
        
        # 序列化消息
        message_bytes = json.dumps(message_copy, separators=(',', ':')).encode('utf-8')
        
        # 解碼簽名
        signature_bytes = base64.b64decode(signature)
        
        # 如果是系統自己的DID，使用系統公鑰
        if from_did == current_app.config.get('ISSUER_DID'):
            public_key = load_public_key()
            return verify_signature(message_bytes, signature_bytes, public_key)
        else:
            # 獲取DID文檔
            did_doc = fetch_did_document(from_did)
            
            # 獲取驗證方法
            verification_method = get_verification_method(did_doc)
            
            # 根據驗證方法類型獲取和使用公鑰
            method_type = verification_method.get('type')
            
            if method_type in ["Ed25519VerificationKey2018", "Ed25519VerificationKey2020"]:
                # 使用Ed25519鑰匙
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                
                if 'publicKeyBase58' in verification_method:
                    import base58
                    public_key_bytes = base58.b58decode(verification_method['publicKeyBase58'])
                    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                    
                    try:
                        public_key.verify(signature_bytes, message_bytes)
                        return True
                    except Exception as e:
                        current_app.logger.error(f"Ed25519簽名驗證失敗: {str(e)}")
                        return False
                        
                elif 'publicKeyMultibase' in verification_method:
                    # 處理multibase格式
                    multibase = verification_method['publicKeyMultibase']
                    if multibase.startswith('z'):
                        import base58
                        public_key_bytes = base58.b58decode(multibase[1:])
                        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                        
                        try:
                            public_key.verify(signature_bytes, message_bytes)
                            return True
                        except Exception as e:
                            current_app.logger.error(f"Ed25519簽名驗證失敗: {str(e)}")
                            return False
                    
                    else:
                        current_app.logger.error(f"不支持的multibase格式: {multibase}")
                        return False
                
                elif 'publicKeyJwk' in verification_method:
                    # 處理JWK格式
                    jwk = verification_method['publicKeyJwk']
                    if jwk.get('kty') == 'OKP' and jwk.get('crv') == 'Ed25519':
                        x = jwk.get('x')
                        if x:
                            public_key_bytes = base64.urlsafe_b64decode(x + '==')
                            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
                            
                            try:
                                public_key.verify(signature_bytes, message_bytes)
                                return True
                            except Exception as e:
                                current_app.logger.error(f"Ed25519簽名驗證失敗: {str(e)}")
                                return False
                    
                    current_app.logger.error(f"不支持的JWK格式: {jwk}")
                    return False
                
                else:
                    current_app.logger.error(f"驗證方法缺少公鑰信息: {verification_method}")
                    return False
            
            else:
                current_app.logger.error(f"不支持的驗證方法類型: {method_type}")
                return False
                
    except Exception as e:
        current_app.logger.error(f"簽名驗證錯誤: {str(e)}")
        return False

def sign_didcomm_message(message: Dict[str, Any]) -> str:
    """
    對DIDComm消息進行簽名
    
    Args:
        message: DIDComm消息
    
    Returns:
        Base64編碼的簽名
    """
    # 序列化消息
    message_bytes = json.dumps(message, separators=(',', ':')).encode('utf-8')
    
    # 使用系統私鑰簽名
    private_key = load_private_key()
    signature_bytes = sign_message(message_bytes, private_key)
    
    # Base64編碼簽名
    return base64.b64encode(signature_bytes).decode('utf-8')

def process_did_auth_request(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    處理DID認證請求
    
    Args:
        message: DIDComm消息
    
    Returns:
        回應消息
    """
    message_id = message.get('id')
    from_did = message.get('from')
    to_did = current_app.config.get('ISSUER_DID')
    body = message.get('body', {})
    
    # 檢查必要字段
    challenge = body.get('challenge')
    application_id = body.get('application_id')
    
    if not challenge:
        return create_problem_report(
            message_id, to_did, from_did, 
            "Missing challenge in DID authentication request"
        )
    
    if not application_id:
        return create_problem_report(
            message_id, to_did, from_did, 
            "Missing application_id in DID authentication request"
        )
    
    # 查找申請
    application = Application.query.get(application_id)
    if not application:
        return create_problem_report(
            message_id, to_did, from_did, 
            f"Application not found: {application_id}"
        )
    
    # 創建認證回應
    response = {
        "id": str(uuid.uuid4()),
        "type": MESSAGE_TYPES['DID_AUTH_RESPONSE'],
        "from": to_did,
        "to": from_did,
        "created_time": datetime.utcnow().isoformat(),
        "body": {
            "challenge": challenge,
            "application_id": application_id,
            "status": "success"
        }
    }
    
    # 簽名回應
    signature = sign_didcomm_message(response)
    response["signature"] = signature
    
    return response

def process_did_auth_response(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    處理DID認證回應
    
    Args:
        message: DIDComm消息
    
    Returns:
        回應消息
    """
    message_id = message.get('id')
    from_did = message.get('from')
    to_did = message.get('to', current_app.config.get('ISSUER_DID'))
    body = message.get('body', {})
    
    # 檢查必要字段
    challenge = body.get('challenge')
    application_id = body.get('application_id')
    
    if not all([challenge, application_id]):
        return create_problem_report(
            message_id, to_did, from_did, 
            "Missing required fields in DID authentication response"
        )
    
    # 創建申請數據請求
    response = {
        "id": str(uuid.uuid4()),
        "type": MESSAGE_TYPES['APPLICATION_DATA_REQUEST'],
        "from": to_did,
        "to": from_did,
        "created_time": datetime.utcnow().isoformat(),
        "body": {
            "application_id": application_id,
            "required_fields": [
                "national_id",
                "name",
                "birth_date",
                "gender",
                "address",
                "birth_place"
            ]
        }
    }
    
    # 簽名回應
    signature = sign_didcomm_message(response)
    response["signature"] = signature
    
    return response

def process_application_data(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    處理申請數據回應
    
    Args:
        message: DIDComm消息
    
    Returns:
        回應消息
    """
    message_id = message.get('id')
    from_did = message.get('from')
    to_did = message.get('to', current_app.config.get('ISSUER_DID'))
    body = message.get('body', {})
    
    # 檢查必要字段
    application_id = body.get('application_id')
    applicant_data = body.get('applicant_data', {})
    
    if not application_id or not applicant_data:
        return create_problem_report(
            message_id, to_did, from_did, 
            "Missing required fields in application data response"
        )
    
    # 獲取申請數據
    national_id = applicant_data.get('national_id')
    name = applicant_data.get('name')
    birth_date_str = applicant_data.get('birth_date')
    gender = applicant_data.get('gender')
    address = applicant_data.get('address')
    birth_place = applicant_data.get('birth_place', '')
    
    # 檢查必要字段
    if not all([national_id, name, birth_date_str, gender, address]):
        return create_problem_report(
            message_id, to_did, from_did, 
            "Missing required personal information"
        )
    
    # 獲取申請記錄
    application = Application.query.get(application_id)
    if not application:
        return create_problem_report(
            message_id, to_did, from_did, 
            f"Application not found: {application_id}"
        )
    
    # 轉換日期格式
    try:
        birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
    except ValueError:
        return create_problem_report(
            message_id, to_did, from_did, 
            "Invalid birth date format"
        )
    
    # 更新申請信息
    application.applicant_did = from_did
    application.national_id = national_id
    application.name = name
    application.birth_date = birth_date
    application.gender = gender
    application.address = address
    application.birth_place = birth_place
    
    # 保存更新
    db.session.commit()
    
    # 創建回應
    response = {
        "id": str(uuid.uuid4()),
        "type": "https://didcomm.org/application/1.0/data-confirmation",
        "from": to_did,
        "to": from_did,
        "created_time": datetime.utcnow().isoformat(),
        "thread": {
            "thid": message_id
        },
        "body": {
            "application_id": application_id,
            "status": "success",
            "message": "Application data received and processed successfully"
        }
    }
    
    # 簽名回應
    signature = sign_didcomm_message(response)
    response["signature"] = signature
    
    return response

def process_credential_request(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    處理憑證請求
    
    Args:
        message: DIDComm消息
    
    Returns:
        回應消息
    """
    message_id = message.get('id')
    from_did = message.get('from')
    to_did = message.get('to', current_app.config.get('ISSUER_DID'))
    body = message.get('body', {})
    
    # 檢查必要字段
    pre_auth_code = body.get('pre_auth_code')
    credential_type = body.get('credential_type')
    
    if not pre_auth_code:
        return create_problem_report(
            message_id, to_did, from_did, 
            "Missing pre_auth_code in credential request"
        )
    
    if not credential_type or credential_type != "NaturalPersonCredential":
        return create_problem_report(
            message_id, to_did, from_did, 
            f"Unsupported credential type: {credential_type}"
        )
    
    # 查找憑證
    credential = Credential.query.filter_by(pre_auth_code=pre_auth_code, is_used=False).first()
    if not credential or not credential.verify_pre_auth_code(pre_auth_code):
        return create_problem_report(
            message_id, to_did, from_did, 
            "Invalid or expired pre-authorized code"
        )
    
    # 獲取申請資料
    application = Application.query.get(credential.application_id)
    if not application or application.applicant_did != from_did:
        return create_problem_report(
            message_id, to_did, from_did, 
            "DID mismatch or application not found"
        )
    
    # 生成憑證有效期
    issued_at = datetime.utcnow()
    expires_at = issued_at.replace(year=issued_at.year + 1)  # 1年有效期
    
    # 更新憑證資訊
    credential.issued_at = issued_at
    credential.expires_at = expires_at
    credential.mark_used()
    db.session.commit()
    
    # 生成憑證資料
    credential_data = {
        'nationalIdNumber': application.national_id,
        'name': application.name,
        'birthDate': application.birth_date.isoformat() if application.birth_date else None,
        'gender': application.gender,
        'address': application.address,
        'birthPlace': application.birth_place
    }
    
    # 生成SD-JWT憑證
    try:
        sd_jwt = generate_sd_jwt(
            issuer_did=to_did,
            subject_did=from_did,
            credential_id=credential.credential_id,
            credential_data=credential_data,
            issued_at=int(issued_at.timestamp()),
            expires_at=int(expires_at.timestamp())
        )
        
        # 創建憑證發行消息
        response = {
            "id": str(uuid.uuid4()),
            "type": MESSAGE_TYPES['CREDENTIAL_ISSUE'],
            "from": to_did,
            "to": from_did,
            "created_time": datetime.utcnow().isoformat(),
            "thread": {
                "thid": message_id
            },
            "body": {
                "format": "jwt_sd",
                "credential": sd_jwt,
                "credential_id": credential.credential_id
            }
        }
        
        # 簽名回應
        signature = sign_didcomm_message(response)
        response["signature"] = signature
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"憑證生成錯誤: {str(e)}")
        return create_problem_report(
            message_id, to_did, from_did, 
            f"Error generating credential: {str(e)}"
        )

def process_presentation(message: Dict[str, Any]) -> Dict[str, Any]:
    """
    處理憑證展示
    
    Args:
        message: DIDComm消息
    
    Returns:
        回應消息
    """
    message_id = message.get('id')
    from_did = message.get('from')
    to_did = message.get('to', current_app.config.get('ISSUER_DID'))
    body = message.get('body', {})
    
    # 檢查必要字段
    sd_jwt = body.get('presentation')
    presentation_type = body.get('presentation_type')
    
    if not sd_jwt:
        return create_problem_report(
            message_id, to_did, from_did, 
            "Missing presentation in message"
        )
    
    if not presentation_type or presentation_type != "jwt_sd":
        return create_problem_report(
            message_id, to_did, from_did, 
            f"Unsupported presentation type: {presentation_type}"
        )
    
    # 驗證憑證
    from app.services.credential import verify_sd_jwt
    is_valid, error_msg, verified_payload = verify_sd_jwt(
        sd_jwt,
        expected_issuer=to_did
    )
    
    if not is_valid:
        return create_problem_report(
            message_id, to_did, from_did,
            f"Invalid credential: {error_msg}"
        )
    
    # 檢查憑證是否有效
    credential_id = verified_payload.get('jti')
    credential = Credential.query.filter_by(credential_id=credential_id).first()
    
    if not credential:
        return create_problem_report(
            message_id, to_did, from_did,
            "Credential not found in system"
        )
    
    if credential.status != 'valid':
        return create_problem_report(
            message_id, to_did, from_did,
            f"Credential has been {credential.status}"
        )
    
    # 創建驗證結果消息
    response = {
        "id": str(uuid.uuid4()),
        "type": MESSAGE_TYPES['VERIFICATION_RESULT'],
        "from": to_did,
        "to": from_did,
        "created_time": datetime.utcnow().isoformat(),
        "thread": {
            "thid": message_id
        },
        "body": {
            "verified": True,
            "verification_result": {
                "credential_id": credential_id,
                "issuer": verified_payload.get('iss'),
                "subject": verified_payload.get('sub'),
                "issued_at": datetime.fromtimestamp(verified_payload.get('iat')).isoformat(),
                "expires_at": datetime.fromtimestamp(verified_payload.get('exp')).isoformat(),
                "disclosed_claims": verified_payload.get('disclosed', {})
            }
        }
    }
    
    # 簽名回應
    signature = sign_didcomm_message(response)
    response["signature"] = signature
    
    return response

def create_problem_report(reply_to_id: str, from_did: str, to_did: Optional[str], error: str) -> Dict[str, Any]:
    """
    創建問題報告
    
    Args:
        reply_to_id: 回應的消息ID
        from_did: 發送者DID
        to_did: 接收者DID
        error: 錯誤消息
    
    Returns:
        問題報告消息
    """
    report = {
        "id": str(uuid.uuid4()),
        "type": MESSAGE_TYPES['PROBLEM_REPORT'],
        "from": from_did,
        "to": to_did,
        "created_time": datetime.utcnow().isoformat(),
        "thread": {
            "thid": reply_to_id
        },
        "body": {
            "code": "error",
            "comment": error
        }
    }
    
    # 簽名報告
    signature = sign_didcomm_message(report)
    report["signature"] = signature
    
    return report

def create_credential_offer(applicant_did: str, pre_auth_code: str, expires_at: Optional[datetime] = None) -> Dict[str, Any]:
    """
    創建憑證提供消息
    
    Args:
        applicant_did: 申請者DID
        pre_auth_code: 預授權碼
        expires_at: 過期時間
    
    Returns:
        憑證提供消息
    """
    issuer_did = current_app.config.get('ISSUER_DID')
    
    offer = {
        "id": str(uuid.uuid4()),
        "type": MESSAGE_TYPES['CREDENTIAL_OFFER'],
        "from": issuer_did,
        "to": applicant_did,
        "created_time": datetime.utcnow().isoformat(),
        "body": {
            "credential_type": "NaturalPersonCredential",
            "pre_auth_code": pre_auth_code,
            "expires_at": expires_at.isoformat() if expires_at else None
        }
    }
    
    # 簽名提供
    signature = sign_didcomm_message(offer)
    offer["signature"] = signature
    
    return offer