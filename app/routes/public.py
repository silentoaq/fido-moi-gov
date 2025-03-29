from flask import Blueprint, jsonify, request, render_template, current_app, redirect, url_for, flash
import json
import time
from app import db
from app.models.credential import Application, PreAuthCode, AccessToken, Credential
from app.utils.did import get_did_document
from app.utils.jwt import generate_pre_auth_code, validate_pre_auth_code, generate_access_token
from app.utils.jwt import validate_access_token, generate_c_nonce, generate_credential
from app.utils.crypto import validate_did_proof
import uuid
from datetime import datetime, timedelta

bp = Blueprint('public', __name__)

@bp.route('/')
def index():
    """首頁路由"""
    return render_template('public/index.html')

@bp.route('/.well-known/did.json')
def did_document():
    """返回符合did:web標準的DID文檔"""
    return jsonify(get_did_document())

@bp.route('/.well-known/openid-credential-issuer')
def openid_credential_issuer():
    """返回OID4VCI發行者元數據"""
    host = request.host
    base_url = f"{current_app.config['ISSUER_PROTOCOL']}://{host}"
    
    # 符合OID4VCI標準的元數據
    return jsonify({
        "credential_issuer": base_url,
        "authorization_servers": [base_url],
        "credential_endpoint": f"{base_url}/credential",
        "token_endpoint": f"{base_url}/token",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "credential_configurations": {
            "TaiwanNaturalPersonCredential": {
                "format": "jwt_sd",
                "scope": "tw_person_credential",
                "cryptographic_binding_methods_supported": ["did"],
                "credential_signing_alg_values_supported": ["EdDSA", "ES256"],
                "display": [
                    {
                        "name": "臺灣自然人憑證",
                        "locale": "zh-TW", 
                        "logo": {
                            "url": f"{base_url}/static/img/credential-logo.png",
                            "alt_text": "臺灣自然人憑證標誌"
                        },
                        "background_color": "#0066CC",
                        "text_color": "#FFFFFF"
                    },
                    {
                        "name": "Taiwan Natural Person Credential",
                        "locale": "en-US"
                    }
                ],
                "claims": {
                    "name": {
                        "display": [{"name": "姓名", "locale": "zh-TW"}, {"name": "Full Name", "locale": "en-US"}]
                    },
                    "birthDate": {
                        "display": [{"name": "出生日期", "locale": "zh-TW"}, {"name": "Birth Date", "locale": "en-US"}]
                    },
                    "nationalId": {
                        "display": [{"name": "身分證字號", "locale": "zh-TW"}, {"name": "National ID", "locale": "en-US"}]
                    }
                }
            }
        },
        "credential_issuer_metadata": {
            "credential_issuer_name": "臺灣自然人憑證發行機構",
            "credential_issuer_name#en-US": "Taiwan Natural Person Credential Issuer",
            "credential_issuer_id": base_url,
            "logo_uri": f"{base_url}/static/img/issuer-logo.png",
            "credential_request_policy": {
                "issuer_validation_methods": ["did_web"]
            }
        }
    })

@bp.route('/.well-known/jwks.json')
def jwks():
    """提供公鑰資訊用於驗證簽名"""
    from app.utils.crypto import get_public_key_jwk
    return jsonify({
        "keys": [get_public_key_jwk()]
    })

@bp.route('/credential-offer')
def credential_offer():
    """生成憑證發行邀請(QR碼)"""
    # 生成預授權碼並存儲
    pre_auth_code, expires_at = generate_pre_auth_code()
    
    # 創建預授權碼記錄
    new_pre_auth = PreAuthCode(
        code=pre_auth_code,
        expires_at=expires_at
    )
    db.session.add(new_pre_auth)
    db.session.commit()
    
    # 構建憑證發行邀請
    host = request.host
    base_url = f"{current_app.config['ISSUER_PROTOCOL']}://{host}"
    offer_data = {
        "credential_issuer": base_url,
        "credential_configuration_ids": ["TaiwanNaturalPersonCredential"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_auth_code,
                "user_pin_required": False
            }
        }
    }
    
    # 渲染QR碼頁面
    offer_uri = f"openid-credential-offer://?credential_offer={json.dumps(offer_data)}"
    return render_template('public/credential_offer.html', offer_uri=offer_uri)

@bp.route('/token', methods=['POST'])
def token_endpoint():
    """處理OAuth2令牌請求"""
    # 獲取預授權碼
    pre_auth_code = request.form.get('pre-authorized_code')
    grant_type = request.form.get('grant_type')
    
    # 驗證grant_type和預授權碼
    if grant_type != 'urn:ietf:params:oauth:grant-type:pre-authorized_code':
        return jsonify({"error": "unsupported_grant_type"}), 400
    
    # 驗證預授權碼有效性
    pre_auth = validate_pre_auth_code(pre_auth_code)
    if not pre_auth:
        return jsonify({"error": "invalid_grant"}), 400
    
    # 生成訪問令牌
    access_token, expires_at = generate_access_token(pre_auth.code)
    
    # 儲存訪問令牌
    new_token = AccessToken(
        token=access_token,
        pre_auth_code=pre_auth.code,
        expires_at=expires_at
    )
    
    # 標記預授權碼已使用
    pre_auth.is_used = True
    
    db.session.add(new_token)
    db.session.commit()
    
    # 生成nonce
    c_nonce = generate_c_nonce()
    
    # 返回令牌響應
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "c_nonce": c_nonce,
        "c_nonce_expires_in": 300
    })

@bp.route('/credential', methods=['POST'])
def credential_endpoint():
    """處理憑證請求並發行憑證"""
    # 驗證Bearer令牌
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "invalid_token"}), 401
    
    token = auth_header[7:]
    token_data = validate_access_token(token)
    if not token_data:
        return jsonify({"error": "invalid_token"}), 401
    
    # 驗證申請表單數據
    data = request.json
    if data.get('format') != 'jwt_sd' or not data.get('credential_configuration_id') == 'TaiwanNaturalPersonCredential':
        return jsonify({"error": "unsupported_credential_type"}), 400
    
    # 獲取申請記錄
    pre_auth = PreAuthCode.query.filter_by(code=token_data['pre_auth_code']).first()
    if not pre_auth or not pre_auth.application_id:
        return jsonify({"error": "invalid_request"}), 400
    
    application = Application.query.get(pre_auth.application_id)
    if not application or application.status != 'approved':
        return jsonify({"error": "application_not_approved"}), 400
    
    # 生成SD-JWT憑證
    credential_data = generate_credential(
        holder_did=application.holder_did,
        name=application.name,
        birth_date=application.birth_date.isoformat(),
        national_id=application.national_id
    )
    
    # 保存憑證記錄
    expires_at = datetime.utcnow() + current_app.config['CREDENTIAL_EXPIRES']
    new_credential = Credential(
        id=credential_data.get('credential_id'),
        application_id=application.id,
        holder_did=application.holder_did,
        sd_jwt=credential_data.get('sd_jwt'),
        disclosures=credential_data.get('disclosures'),
        expires_at=expires_at
    )
    
    # 更新申請狀態
    application.status = 'issued'
    application.credential_id = new_credential.id
    
    db.session.add(new_credential)
    db.session.commit()
    
    # 返回憑證和披露資訊
    return jsonify({
        "format": "jwt_sd",
        "credential": credential_data.get('sd_jwt'),
        "disclosures": credential_data.get('disclosures')
    })

@bp.route('/submit-application', methods=['POST'])
def submit_application():
    """接收Holder提交的申請資料"""
    # 驗證請求
    data = request.json
    pre_auth_code = data.get('pre_authorized_code')
    holder_did = data.get('holder_did')
    proof = data.get('proof')
    
    # 驗證DID證明
    if not validate_did_proof(holder_did, proof):
        return jsonify({"error": "invalid_proof"}), 400
    
    # 驗證預授權碼
    pre_auth = validate_pre_auth_code(pre_auth_code)
    if not pre_auth:
        return jsonify({"error": "invalid_pre_auth_code"}), 400
    
    # 提取申請資料
    credential_application = data.get('credential_application', {})
    name = credential_application.get('name')
    birth_date_str = credential_application.get('birth_date')
    national_id = credential_application.get('national_id')
    
    # 基本驗證
    if not all([name, birth_date_str, national_id]):
        return jsonify({"error": "missing_required_fields"}), 400
    
    try:
        birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({"error": "invalid_date_format"}), 400
    
    # 創建申請記錄
    application = Application(
        id=str(uuid.uuid4()),
        holder_did=holder_did,
        name=name,
        birth_date=birth_date,
        national_id=national_id,
        status="pending",
        pre_auth_code=pre_auth_code
    )
    
    # 關聯預授權碼與申請
    pre_auth.application_id = application.id
    
    db.session.add(application)
    db.session.commit()
    
    # 返回申請確認
    return jsonify({
        "status": "pending",
        "application_id": application.id,
        "message": "您的申請已提交，請等待審核"
    })

@bp.route('/credential-status/<credential_id>')
def credential_status(credential_id):
    """提供憑證狀態查詢"""
    credential = Credential.query.get(credential_id)
    if not credential:
        return jsonify({"error": "credential_not_found"}), 404
    
    status_info = {
        "id": credential.id,
        "status": "revoked" if credential.is_revoked else "valid",
        "issued_at": credential.issued_at.isoformat(),
        "expires_at": credential.expires_at.isoformat()
    }
    
    if credential.is_revoked:
        status_info["revocation_reason"] = credential.revocation_reason
    
    return jsonify(status_info)