import os
import uuid
import json
import jwt
import time
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app, abort
from app import db
from app.models import Application, Credential
from app.services.credential import generate_sd_jwt

bp = Blueprint('oid4vci', __name__, url_prefix='/api/v1')

# 訪問令牌緩存 (實際生產環境應使用Redis等)
access_tokens = {}

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
    # 檢查請求格式
    if not request.is_json:
        return jsonify({"error": "unsupported_content_type"}), 415

    data = request.json
    
    # 檢查授權類型
    grant_type = data.get('grant_type')
    if grant_type != 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        return jsonify({"error": "unsupported_grant_type"}), 400
    
    # 獲取預授權碼
    pre_auth_code = data.get('pre-authorized_code')
    if not pre_auth_code:
        return jsonify({"error": "invalid_request", "error_description": "Missing pre-authorized_code"}), 400
    
    # 查找並驗證預授權碼
    credential = Credential.query.filter_by(pre_auth_code=pre_auth_code, is_used=False).first()
    if not credential or not credential.verify_pre_auth_code(pre_auth_code):
        return jsonify({"error": "invalid_grant", "error_description": "Invalid or expired pre-authorized code"}), 400
    
    # 生成訪問令牌
    access_token = str(uuid.uuid4())
    expires_in = 300  # 5分鐘有效期
    
    # 儲存令牌關聯 (實際應使用Redis等)
    access_tokens[access_token] = {
        'credential_id': credential.id,
        'expires_at': datetime.utcnow() + timedelta(seconds=expires_in)
    }
    
    # 標記預授權碼為已使用
    credential.mark_used()
    db.session.commit()
    
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
        return jsonify({"error": "unsupported_content_type"}), 415
    
    # 驗證訪問令牌
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "invalid_token"}), 401
    
    access_token = auth_header.split(' ')[1]
    token_info = access_tokens.get(access_token)
    
    if not token_info or token_info['expires_at'] < datetime.utcnow():
        return jsonify({"error": "invalid_token", "error_description": "Token expired or invalid"}), 401
    
    # 獲取關聯憑證
    credential_id = token_info['credential_id']
    credential = Credential.query.get(credential_id)
    
    if not credential or credential.status != 'valid':
        return jsonify({"error": "invalid_request", "error_description": "Invalid credential"}), 400
    
    # 檢查請求的憑證格式
    data = request.json
    format_type = data.get('format')
    if format_type != 'jwt_sd':
        return jsonify({"error": "unsupported_credential_format"}), 400
    
    # 檢查請求的憑證類型
    cred_types = data.get('credential_definition', {}).get('type', [])
    if "NaturalPersonCredential" not in cred_types:
        return jsonify({"error": "unsupported_credential_type"}), 400
    
    # 獲取申請資料
    application = Application.query.get(credential.application_id)
    if not application or not application.applicant_did:
        return jsonify({"error": "invalid_request", "error_description": "Application data not found"}), 400
    
    # 生成憑證有效期 (1年)
    issued_at = datetime.utcnow()
    expires_at = issued_at + timedelta(days=365)
    
    # 更新憑證資訊
    credential.issued_at = issued_at
    credential.expires_at = expires_at
    db.session.commit()
    
    # 生成SD-JWT格式的憑證
    credential_data = {
        'national_id': application.national_id,
        'name': application.name,
        'birth_date': application.birth_date.isoformat(),
        'gender': application.gender,
        'address': application.address,
        'birth_place': application.birth_place
    }
    
    sd_jwt = generate_sd_jwt(
        issuer_did="did:web:fido.moi.gov.tw",
        subject_did=application.applicant_did,
        credential_id=credential.credential_id,
        credential_data=credential_data,
        issued_at=int(issued_at.timestamp()),
        expires_at=int(expires_at.timestamp())
    )
    
    # 移除訪問令牌
    access_tokens.pop(access_token, None)
    
    # 返回憑證
    return jsonify({
        "format": "jwt_sd",
        "credential": sd_jwt
    })

@bp.route('/credential-status/<credential_id>', methods=['GET'])
def credential_status(credential_id):
    """查詢憑證狀態"""
    credential = Credential.query.filter_by(credential_id=credential_id).first()
    
    if not credential:
        return jsonify({"error": "Credential not found"}), 404
    
    # 返回狀態資訊
    status_info = {
        "id": credential.credential_id,
        "status": credential.status,
        "issued_at": credential.issued_at.isoformat() if credential.issued_at else None,
        "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
        "revoked_at": credential.revoked_at.isoformat() if credential.revoked_at else None
    }
    
    return jsonify(status_info)

@bp.route('/verify', methods=['POST'])
def verify_credential():
    """驗證憑證"""
    if not request.is_json:
        return jsonify({"error": "unsupported_content_type"}), 415
    
    data = request.json
    jwt_credential = data.get('credential')
    
    if not jwt_credential:
        return jsonify({"error": "missing_credential"}), 400
    
    try:
        # 解析JWT頭部獲取kid (不驗證簽名)
        header = jwt.get_unverified_header(jwt_credential.split('~')[0])
        kid = header.get('kid')
        
        # 從JWT獲取credential_id
        # 實際項目中需要完整驗證JWT簽名
        payload = jwt.decode(
            jwt_credential.split('~')[0], 
            options={"verify_signature": False}
        )
        credential_id = payload.get('jti')
        
        if not credential_id:
            return jsonify({"error": "invalid_credential"}), 400
        
        # 查詢憑證狀態
        credential = Credential.query.filter_by(credential_id=credential_id).first()
        if not credential:
            return jsonify({"error": "credential_not_found"}), 404
        
        # 檢查是否撤銷
        if credential.status == 'revoked':
            return jsonify({"verified": False, "reason": "credential_revoked"}), 200
        
        # 檢查是否過期
        if credential.expires_at and credential.expires_at < datetime.utcnow():
            return jsonify({"verified": False, "reason": "credential_expired"}), 200
        
        # 這裡應進行完整的密碼學驗證
        # ...
        
        return jsonify({"verified": True, "credential_id": credential_id}), 200
        
    except Exception as e:
        return jsonify({"error": "validation_error", "details": str(e)}), 400