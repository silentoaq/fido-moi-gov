import uuid
import qrcode
import io
import base64
import json
import logging
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, jsonify, abort, current_app
from app import db
from app.models import Application, Credential, DIDCommSession
from app.utils.crypto import sign_message
from app.utils.didcomm import sign_didcomm_message

logger = logging.getLogger(__name__)

bp = Blueprint('public', __name__)

@bp.route('/')
def index():
    """首頁"""
    return render_template('public/index.html')

@bp.route('/application', methods=['GET'])
def application_form():
    """
    申請表單頁面 - 新申請流程
    生成QR碼讓用戶掃描，不再需要用戶在網頁填寫表單
    """
    # 創建新申請記錄（只有基本信息）
    application = Application(
        status='pending',
        challenge=str(uuid.uuid4())  # 為身份驗證生成挑戰碼
    )
    
    db.session.add(application)
    db.session.commit()
    
    # 創建DIDComm會話記錄
    session = DIDCommSession(
        application_id=application.id,
        thread_id=str(uuid.uuid4()),
        from_did=current_app.config.get('ISSUER_DID'),
        to_did="unknown",  # 用戶DID尚未知
        session_type="auth",
        status="active",
        challenge=application.challenge,
        expires_at=datetime.utcnow().replace(hour=23, minute=59, second=59)  # 當天有效
    )
    
    db.session.add(session)
    db.session.commit()
    
    # 生成DIDComm消息
    issuer_did = current_app.config.get('ISSUER_DID')
    did_auth_request = {
        "type": "https://didcomm.org/did-auth/1.0/request",
        "id": str(uuid.uuid4()),
        "from": issuer_did,
        "created_time": datetime.utcnow().isoformat(),
        "body": {
            "challenge": application.challenge,
            "application_id": application.id,
            "thread_id": session.thread_id
        }
    }
    
    # 簽名DIDComm消息
    signature = sign_didcomm_message(did_auth_request)
    did_auth_request["signature"] = signature
    
    # 編碼為URL安全的字符串
    didcomm_message_json = json.dumps(did_auth_request)
    didcomm_message_encoded = base64.urlsafe_b64encode(didcomm_message_json.encode('utf-8')).decode('utf-8')
    
    # 創建QR碼內容 - 生產環境使用正確的域名
    qr_content = f"didcomm://request?message={didcomm_message_encoded}"
    
    # 生成QR碼圖像
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_content)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 將圖片轉換為base64字符串
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    logger.info(f"創建新申請: {application.id}, 等待用戶掃描QR碼")
    
    return render_template('public/application_scan.html', 
                          application=application,
                          qr_code=img_str,
                          qr_content=qr_content)

@bp.route('/api/v1/application/<application_id>/status', methods=['GET'])
def application_status_api(application_id):
    """
    API端點：獲取申請狀態
    用於前端JS輪詢以獲取狀態更新
    """
    try:
        # 獲取申請記錄
        application = Application.query.get_or_404(application_id)
        
        # 返回狀態信息
        return jsonify({
            "id": application.id,
            "status": application.status,
            "has_did": bool(application.applicant_did),
            "is_complete": application.is_complete(),
            "updated_at": application.updated_at.isoformat()
        })
        
    except Exception as e:
        logger.error(f"獲取申請狀態錯誤: {str(e)}")
        return jsonify({
            "error": "server_error",
            "error_description": "Failed to get application status",
            "details": str(e)
        }), 500

@bp.route('/application/<application_id>/status')
def application_status(application_id):
    """申請狀態頁面"""
    application = Application.query.get_or_404(application_id)
    
    # 如果申請已批准，獲取相關憑證
    credential = None
    if application.status == 'approved':
        credential = Credential.query.filter_by(application_id=application_id).first()
    
    return render_template('public/application_status.html', 
                          application=application,
                          credential=credential)

@bp.route('/application/<application_id>/credential')
def application_credential(application_id):
    """
    憑證獲取頁面 - 顯示QR碼讓用戶掃描獲取憑證
    """
    application = Application.query.get_or_404(application_id)
    
    # 檢查申請是否已批准
    if application.status != 'approved':
        flash('您的申請尚未批准', 'warning')
        return redirect(url_for('public.application_status', application_id=application_id))
    
    # 獲取關聯憑證
    credential = Credential.query.filter_by(application_id=application_id).first()
    
    if not credential:
        flash('無法找到相關憑證', 'danger')
        return redirect(url_for('public.application_status', application_id=application_id))
    
    # 檢查是否已發行
    if credential.issued_at:
        flash('憑證已發行，請在數位皮夾中查看', 'info')
        return redirect(url_for('public.application_status', application_id=application_id))
    
    # 確保憑證有預授權碼
    if not credential.pre_auth_code or not credential.code_expires_at:
        credential.generate_pre_auth_code()
        db.session.commit()
    
    # 創建DIDComm會話
    session = DIDCommSession(
        application_id=application.id,
        credential_id=credential.id,
        thread_id=str(uuid.uuid4()),
        from_did=current_app.config.get('ISSUER_DID'),
        to_did=application.applicant_did,  # 已知用戶DID
        session_type="issuance",
        status="active",
        expires_at=credential.code_expires_at
    )
    
    db.session.add(session)
    db.session.commit()
    
    # 創建憑證提供DIDComm消息
    credential_offer = {
        "type": "https://didcomm.org/issue-credential/1.0/offer",
        "id": str(uuid.uuid4()),
        "from": current_app.config.get('ISSUER_DID'),
        "to": application.applicant_did,
        "created_time": datetime.utcnow().isoformat(),
        "thread_id": session.thread_id,
        "body": {
            "credential_type": "NaturalPersonCredential",
            "pre_auth_code": credential.pre_auth_code,
            "expires_at": credential.code_expires_at.isoformat() if credential.code_expires_at else None
        }
    }
    
    # 簽名DIDComm消息
    signature = sign_didcomm_message(credential_offer)
    credential_offer["signature"] = signature
    
    # 編碼為URL安全的字符串
    didcomm_message_json = json.dumps(credential_offer)
    didcomm_message_encoded = base64.urlsafe_b64encode(didcomm_message_json.encode('utf-8')).decode('utf-8')
    
    # 創建QR碼內容
    qr_content = f"didcomm://credential-offer?message={didcomm_message_encoded}"
    
    # 生成QR碼圖像
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(qr_content)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 將圖片轉換為base64字符串
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    logger.info(f"生成憑證獲取QR碼, 申請ID: {application.id}, 憑證ID: {credential.id}")
    
    return render_template('public/application_credential.html', 
                          application=application,
                          credential=credential,
                          qr_code=img_str,
                          qr_content=qr_content)

@bp.route('/application/lookup', methods=['GET', 'POST'])
def application_lookup():
    """申請查詢頁面"""
    if request.method == 'POST':
        application_id = request.form.get('application_id')
        if not application_id:
            flash('請輸入申請ID', 'danger')
            return render_template('public/application_lookup.html')
        
        # 驗證申請ID是否存在
        application = Application.query.get(application_id)
        if not application:
            flash('找不到該申請ID，請確認後重試', 'danger')
            return render_template('public/application_lookup.html')
            
        return redirect(url_for('public.application_status', application_id=application_id))
    
    return render_template('public/application_lookup.html')