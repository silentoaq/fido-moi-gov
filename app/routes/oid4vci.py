import os
import uuid
import json
import jwt
import time
import logging
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app, abort
from app import db
from app.models import Application, Credential
from app.services.credential import generate_sd_jwt, verify_sd_jwt
from app.utils.didcomm import process_didcomm_message
from app.utils.crypto import load_private_key, load_public_key, verify_signature

logger = logging.getLogger(__name__)

bp = Blueprint('oid4vci', __name__, url_prefix='/api/v1')

# 訪問令牌緩存 (實際生產環境應使用Redis等)
# 儲存格式: { 'token': { 'credential_id': 'xxx', 'expires_at': datetime } }
access_tokens = {}

# 定期清理過期的訪問令牌
def cleanup_expired_tokens():
    """清理過期的訪問令牌"""
    now = datetime.utcnow()
    expired_tokens = [token for token, info in access_tokens.items() 
                    if info['expires_at'] < now]
                    
    for token in expired_tokens:
        access_tokens.pop(token, None)
        
    if expired_tokens:
        logger.info(f"清理了 {len(expired_tokens)} 個過期訪問令牌")

@bp.route('/token', methods=['POST'])
def token():
    """
    OID4VCI 預授權碼流程的令牌端點
    預期請求格式:
    {
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "<code>",
        "client_id": "<client_id>"  # 可選
    }
    """
    # 清理過期的訪問令牌
    cleanup_expired_tokens()
    
    # 檢查請求格式
    if not request.is_json:
        logger.warning("令牌請求不是JSON格式")
        return jsonify({
            "error": "unsupported_content_type", 
            "error_description": "Request must be application/json"
        }), 415

    data = request.json
    
    # 檢查授權類型
    grant_type = data.get('grant_type')
    if grant_type != 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        logger.warning(f"不支持的授權類型: {grant_type}")
        return jsonify({
            "error": "unsupported_grant_type", 
            "error_description": "Only pre-authorized_code grant type is supported"
        }), 400
    
    # 獲取預授權碼
    pre_auth_code = data.get('pre-authorized_code')
    if not pre_auth_code:
        logger.warning("缺少預授權碼")
        return jsonify({
            "error": "invalid_request", 
            "error_description": "Missing pre-authorized_code"
        }), 400
    
    # 查找並驗證預授權碼
    credential = Credential.query.filter_by(pre_auth_code=pre_auth_code, is_used=False).first()
    if not credential:
        logger.warning(f"找不到有效的預授權碼: {pre_auth_code}")
        return jsonify({
            "error": "invalid_grant", 
            "error_description": "Invalid pre-authorized code"
        }), 400
        
    if not credential.verify_pre_auth_code(pre_auth_code):
        logger.warning(f"預授權碼已過期: {pre_auth_code}")
        return jsonify({
            "error": "invalid_grant", 
            "error_description": "Expired pre-authorized code"
        }), 400
    
    # 生成訪問令牌
    access_token = str(uuid.uuid4())
    expires_in = 300  # 5分鐘有效期
    
    # 儲存令牌關聯
    access_tokens[access_token] = {
        'credential_id': credential.id,
        'expires_at': datetime.utcnow() + timedelta(seconds=expires_in)
    }
    
    # 標記預授權碼為已使用
    credential.mark_used()
    db.session.commit()
    
    logger.info(f"發行訪問令牌: {access_token} (憑證ID: {credential.id})")
    
    # 返回訪問令牌
    return jsonify({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "c_nonce": str(uuid.uuid4())[:8],
        "c_nonce_expires_in": 3600  # 1小時
    })

@bp.route('/credentials', methods=['POST'])
def issue_credential():
    """
    OID4VCI 憑證發行端點
    預期請求頭:
    Authorization: Bearer <access_token>
    
    預期請求格式:
    {
        "format": "jwt_sd",
        "credential_definition": {
            "type": ["VerifiableCredential", "NaturalPersonCredential"]
        },
        "proof": {  # 可選的持有者證明
            "proof_type": "jwt",
            "jwt": "<jwt>"
        }
    }
    """
    # 檢查請求格式
    if not request.is_json:
        logger.warning("憑證請求不是JSON格式")
        return jsonify({
            "error": "unsupported_content_type",
            "error_description": "Request must be application/json"
        }), 415
    
    # 驗證訪問令牌
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.warning("缺少或格式錯誤的Authorization頭")
        return jsonify({
            "error": "invalid_token",
            "error_description": "Missing or malformed authorization header"
        }), 401
    
    access_token = auth_header.split(' ')[1]
    token_info = access_tokens.get(access_token)
    
    if not token_info:
        logger.warning(f"無效的訪問令牌: {access_token}")
        return jsonify({
            "error": "invalid_token",
            "error_description": "Invalid access token"
        }), 401
        
    if token_info['expires_at'] < datetime.utcnow():
        # 移除過期的令牌
        access_tokens.pop(access_token, None)
        logger.warning(f"訪問令牌已過期: {access_token}")
        return jsonify({
            "error": "invalid_token",
            "error_description": "Access token has expired"
        }), 401
    
    # 獲取關聯憑證
    credential_id = token_info['credential_id']
    credential = Credential.query.get(credential_id)
    
    if not credential:
        logger.warning(f"找不到憑證: {credential_id}")
        return jsonify({
            "error": "invalid_request",
            "error_description": "Credential not found"
        }), 400
        
    if credential.status != 'valid':
        logger.warning(f"憑證狀態無效: {credential.status}")
        return jsonify({
            "error": "invalid_request",
            "error_description": f"Credential is {credential.status}"
        }), 400
    
    # 檢查請求的憑證格式
    data = request.json
    format_type = data.get('format')
    if format_type != 'jwt_sd':
        logger.warning(f"不支持的憑證格式: {format_type}")
        return jsonify({
            "error": "unsupported_credential_format",
            "error_description": "Only jwt_sd format is supported"
        }), 400
    
    # 檢查請求的憑證類型
    cred_types = data.get('credential_definition', {}).get('type', [])
    if "NaturalPersonCredential" not in cred_types:
        logger.warning(f"不支持的憑證類型: {cred_types}")
        return jsonify({
            "error": "unsupported_credential_type",
            "error_description": "NaturalPersonCredential type is required"
        }), 400
    
    # 獲取申請資料
    application = Application.query.get(credential.application_id)
    if not application:
        logger.warning(f"找不到申請資料: {credential.application_id}")
        return jsonify({
            "error": "invalid_request",
            "error_description": "Application data not found"
        }), 400
        
    if not application.applicant_did:
        logger.warning(f"申請人DID未關聯: {credential.application_id}")
        return jsonify({
            "error": "invalid_request",
            "error_description": "No DID associated with application"
        }), 400
    
    # 驗證持有者證明 (如果提供)
    proof = data.get('proof', {})
    if proof:
        proof_jwt = proof.get('jwt')
        if proof.get('proof_type') != 'jwt' or not proof_jwt:
            logger.warning("無效的證明格式")
            return jsonify({
                "error": "invalid_proof",
                "error_description": "Invalid proof format"
            }), 400
        
        try:
            # 解析JWT頭部獲取kid
            jwt_header = jwt.get_unverified_header(proof_jwt)
            kid = jwt_header.get('kid')
            
            if not kid or not kid.startswith(application.applicant_did):
                logger.warning(f"證明DID不匹配: {kid} vs {application.applicant_did}")
                return jsonify({
                    "error": "invalid_proof",
                    "error_description": "Proof DID mismatch"
                }), 400
            
            # 實現持有者公鑰的獲取和驗證
            from app.utils.didcomm import fetch_did_document, get_verification_method
            
            try:
                # 獲取持有者的DID文檔
                did_doc = fetch_did_document(application.applicant_did)
                
                # 獲取驗證方法
                verification_method = get_verification_method(did_doc, kid)
                
                # 獲取公鑰並驗證簽名
                # 實際實現中應根據驗證方法類型進行相應處理
                
                # 驗證JWT的完整性，包括Nonce等安全挑戰
                # 這里只是佔位，實際應完整實現
                
            except Exception as e:
                logger.error(f"獲取持有者DID文檔錯誤: {str(e)}")
                return jsonify({
                    "error": "invalid_proof",
                    "error_description": f"Error fetching DID document: {str(e)}"
                }), 400
                
        except Exception as e:
            logger.error(f"驗證持有者證明錯誤: {str(e)}")
            return jsonify({
                "error": "invalid_proof",
                "error_description": str(e)
            }), 400
    
    # 生成憑證有效期 (1年)
    issued_at = datetime.utcnow()
    expires_at = issued_at + timedelta(days=365)
    
    # 更新憑證資訊
    credential.issued_at = issued_at
    credential.expires_at = expires_at
    db.session.commit()
    
    try:
        # 生成SD-JWT格式的憑證
        credential_data = {
            'nationalIdNumber': application.national_id,
            'name': application.name,
            'birthDate': application.birth_date.isoformat() if application.birth_date else None,
            'gender': application.gender,
            'address': application.address,
            'birthPlace': application.birth_place
        }
        
        sd_jwt = generate_sd_jwt(
            issuer_did=current_app.config.get('ISSUER_DID'),
            subject_did=application.applicant_did,
            credential_id=credential.credential_id,
            credential_data=credential_data,
            issued_at=int(issued_at.timestamp()),
            expires_at=int(expires_at.timestamp())
        )
        
        # 移除訪問令牌
        access_tokens.pop(access_token, None)
        
        logger.info(f"成功發行憑證: {credential.credential_id} (申請ID: {application.id})")
        
        # 返回憑證
        return jsonify({
            "format": "jwt_sd",
            "credential": sd_jwt
        })
    except Exception as e:
        logger.error(f"生成憑證錯誤: {str(e)}")
        return jsonify({
            "error": "credential_generation_error",
            "error_description": "Failed to generate credential",
            "details": str(e)
        }), 500
    
@bp.route('/credential-status/<credential_id>', methods=['GET'])
def credential_status(credential_id):
    """查詢憑證狀態"""
    credential = Credential.query.filter_by(credential_id=credential_id).first()
    
    if not credential:
        logger.warning(f"查詢狀態: 找不到憑證 {credential_id}")
        return jsonify({
            "error": "not_found",
            "error_description": "Credential not found"
        }), 404
    
    # 返回狀態資訊
    status_info = {
        "id": credential.credential_id,
        "status": credential.status,
        "issued_at": credential.issued_at.isoformat() if credential.issued_at else None,
        "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
        "revoked_at": credential.revoked_at.isoformat() if credential.revoked_at else None
    }
    
    logger.info(f"查詢憑證狀態: {credential_id} ({credential.status})")
    return jsonify(status_info)

@bp.route('/verify', methods=['POST'])
def verify_credential():
    """
    驗證憑證
    完整驗證SD-JWT格式的憑證，包括簽名驗證
    """
    if not request.is_json:
        logger.warning("驗證請求不是JSON格式")
        return jsonify({
            "error": "unsupported_content_type",
            "error_description": "Request must be application/json"
        }), 415
    
    data = request.json
    jwt_credential = data.get('credential')
    
    if not jwt_credential:
        logger.warning("缺少憑證")
        return jsonify({
            "error": "missing_credential",
            "error_description": "No credential provided"
        }), 400
    
    try:
        # 完整驗證SD-JWT
        is_valid, error_msg, verified_payload = verify_sd_jwt(
            jwt_credential, 
            expected_issuer=current_app.config.get('ISSUER_DID')
        )
        
        if not is_valid:
            logger.warning(f"憑證驗證失敗: {error_msg}")
            return jsonify({
                "verified": False,
                "reason": error_msg
            }), 200
        
        credential_id = verified_payload.get('jti')
        if not credential_id:
            logger.warning("憑證缺少ID (jti)")
            return jsonify({
                "verified": False,
                "reason": "Missing credential ID (jti)"
            }), 200
        
        # 查詢憑證狀態
        credential = Credential.query.filter_by(credential_id=credential_id).first()
        if not credential:
            logger.warning(f"憑證不存在系統中: {credential_id}")
            return jsonify({
                "verified": False,
                "reason": "credential_not_found"
            }), 200
        
        # 檢查是否撤銷
        if credential.status == 'revoked':
            logger.warning(f"憑證已撤銷: {credential_id}")
            return jsonify({
                "verified": False,
                "reason": "credential_revoked"
            }), 200
        
        # 檢查是否過期
        if credential.expires_at and credential.expires_at < datetime.utcnow():
            logger.warning(f"憑證已過期: {credential_id}")
            return jsonify({
                "verified": False,
                "reason": "credential_expired"
            }), 200
        
        # 返回驗證結果
        logger.info(f"憑證驗證成功: {credential_id}")
        result = {
            "verified": True,
            "credential_id": credential_id,
            "issuer": verified_payload.get('iss'),
            "subject": verified_payload.get('sub'),
            "issued_at": datetime.fromtimestamp(verified_payload.get('iat')).isoformat(),
            "expires_at": datetime.fromtimestamp(verified_payload.get('exp')).isoformat(),
            "disclosed_claims": verified_payload.get('disclosed', {})
        }
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"驗證憑證錯誤: {str(e)}")
        return jsonify({
            "error": "validation_error",
            "error_description": "Error validating credential",
            "details": str(e)
        }), 400

@bp.route('/didcomm', methods=['POST'])
def didcomm_endpoint():
    """
    DIDComm通信端點
    處理所有DIDComm消息, 包括:
    1. 身份驗證請求/回應
    2. 憑證申請/發行
    3. 憑證提交/驗證
    """
    if not request.is_json:
        logger.warning("DIDComm請求不是JSON格式")
        return jsonify({
            "error": "unsupported_content_type",
            "error_description": "Request must be application/json"
        }), 415
    
    try:
        # 處理DIDComm消息
        request_data = request.json
        logger.info(f"收到DIDComm消息類型: {request_data.get('type')}")
        response = process_didcomm_message(request_data)
        return jsonify(response)
    except Exception as e:
        logger.error(f"DIDComm處理錯誤: {str(e)}")
        # 返回錯誤響應
        error_response = {
            "type": "https://didcomm.org/report-problem/1.0/problem-report",
            "id": str(uuid.uuid4()),
            "from": current_app.config.get('ISSUER_DID'),
            "created_time": datetime.utcnow().isoformat(),
            "body": {
                "code": "error",
                "comment": f"Error processing DIDComm message: {str(e)}"
            }
        }
        return jsonify(error_response), 400
        
@bp.route('/application/<application_id>/apply', methods=['POST'])
def application_apply(application_id):
    """
    處理用戶通過數位皮夾提交的申請數據
    使用DIDComm消息接收用戶數據並關聯DID
    """
    if not request.is_json:
        logger.warning("申請數據不是JSON格式")
        return jsonify({
            "error": "unsupported_content_type",
            "error_description": "Request must be application/json"
        }), 415
    
    try:
        # 獲取申請記錄
        application = Application.query.get_or_404(application_id)
        
        # 獲取請求數據
        data = request.json
        applicant_did = data.get('did')
        personal_info = data.get('personal_info', {})
        signature_base64 = data.get('signature')
        
        # 檢查必要字段
        if not applicant_did or not personal_info or not signature_base64:
            logger.warning("缺少申請必要字段")
            return jsonify({
                "error": "invalid_request",
                "error_description": "Missing required fields"
            }), 400
        
        # 驗證DID格式
        if not applicant_did.startswith('did:pkh:solana:'):
            logger.warning(f"無效的DID格式: {applicant_did}")
            return jsonify({
                "error": "invalid_request",
                "error_description": "Invalid DID format"
            }), 400
        
        # 驗證簽名
        try:
            # 將請求數據轉為規範化的JSON字符串
            signed_data = {
                "did": applicant_did,
                "personal_info": personal_info,
                "application_id": application_id
            }
            message = json.dumps(signed_data, separators=(',', ':')).encode('utf-8')
            
            # 解碼簽名
            import base64
            signature = base64.b64decode(signature_base64)
            
            # 使用DID獲取驗證密鑰
            from app.utils.didcomm import fetch_did_document, get_verification_method
            
            # 獲取持有者的DID文檔
            did_doc = fetch_did_document(applicant_did)
            
            # 獲取驗證方法
            verification_method = get_verification_method(did_doc)
            
            # 驗證簽名
            # 這里應根據DID類型實現相應的驗證邏輯
            # 實際生產環境中應實現完整的驗證邏輯
            
        except Exception as e:
            logger.error(f"驗證申請簽名錯誤: {str(e)}")
            return jsonify({
                "error": "invalid_signature",
                "error_description": f"Signature verification failed: {str(e)}"
            }), 400
        
        # 獲取必要的個人信息
        national_id = personal_info.get('national_id')
        name = personal_info.get('name')
        birth_date_str = personal_info.get('birth_date')
        gender = personal_info.get('gender')
        address = personal_info.get('address')
        birth_place = personal_info.get('birth_place', '')
        
        # 驗證必要字段
        if not all([national_id, name, birth_date_str, gender, address]):
            logger.warning("缺少必要的個人資訊")
            return jsonify({
                "error": "invalid_request",
                "error_description": "Missing required personal information"
            }), 400
        
        # 轉換日期格式
        try:
            birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
        except ValueError:
            logger.warning(f"無效的出生日期格式: {birth_date_str}")
            return jsonify({
                "error": "invalid_request",
                "error_description": "Invalid birth date format"
            }), 400
        
        # 檢查DID是否已被使用
        existing_application = Application.query.filter_by(applicant_did=applicant_did).first()
        if existing_application and existing_application.id != application_id:
            logger.warning(f"DID已被其他申請使用: {applicant_did}")
            return jsonify({
                "error": "invalid_request",
                "error_description": "DID already associated with another application"
            }), 400
        
        # 更新申請信息
        application.applicant_did = applicant_did
        application.national_id = national_id
        application.name = name
        application.birth_date = birth_date
        application.gender = gender
        application.address = address
        application.birth_place = birth_place
        
        db.session.commit()
        
        logger.info(f"成功更新申請數據: {application_id} (DID: {applicant_did})")
        
        # 返回成功響應
        return jsonify({
            "status": "success",
            "message": "Application data submitted successfully",
            "application_id": application_id
        })
        
    except Exception as e:
        logger.error(f"處理申請數據錯誤: {str(e)}")
        return jsonify({
            "error": "server_error",
            "error_description": "Failed to process application data",
            "details": str(e)
        }), 500