import uuid
import qrcode
import io
import base64
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, jsonify, abort
from app import db
from app.models import Application, Credential

bp = Blueprint('public', __name__)

@bp.route('/')
def index():
    """首頁"""
    return render_template('public/index.html')

@bp.route('/application', methods=['GET', 'POST'])
def application_form():
    """申請表單頁面與處理"""
    if request.method == 'POST':
        # 獲取表單數據
        national_id = request.form.get('national_id')
        name = request.form.get('name')
        birth_date_str = request.form.get('birth_date')
        gender = request.form.get('gender')
        address = request.form.get('address')
        birth_place = request.form.get('birth_place')
        
        # 基本驗證
        if not all([national_id, name, birth_date_str, gender, address, birth_place]):
            flash('請填寫所有必填欄位', 'danger')
            return render_template('public/application_form.html')
        
        try:
            # 轉換日期格式
            birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash('出生日期格式不正確', 'danger')
            return render_template('public/application_form.html')
        
        # 創建新申請
        application = Application(
            national_id=national_id,
            name=name,
            birth_date=birth_date,
            gender=gender,
            address=address,
            birth_place=birth_place,
            status='pending'
        )
        
        db.session.add(application)
        db.session.commit()
        
        flash('申請已提交，請記錄您的申請ID：' + application.id, 'success')
        return redirect(url_for('public.application_connect', application_id=application.id))
    
    return render_template('public/application_form.html')

@bp.route('/application/<application_id>/connect')
def application_connect(application_id):
    """關聯DID的頁面"""
    application = Application.query.get_or_404(application_id)
    
    # 已經關聯DID，跳轉到狀態頁面
    if application.applicant_did:
        return redirect(url_for('public.application_status', application_id=application_id))
    
    # 生成QR碼
    # 在實際項目中，這裡會生成一個包含應用ID的深度連結或特殊URI
    connect_url = f"didholder://connect?application_id={application_id}&issuer=fido.moi.gov.tw"
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(connect_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 將圖片轉換為base64字符串
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('public/application_connect.html', 
                          application=application, 
                          qr_code=img_str,
                          connect_url=connect_url)

@bp.route('/api/application/<application_id>/connect', methods=['POST'])
def application_connect_api(application_id):
    """API端點：關聯DID到申請"""
    application = Application.query.get_or_404(application_id)
    
    if not request.is_json:
        return jsonify({"error": "Invalid content type"}), 415
    
    data = request.json
    applicant_did = data.get('did')
    
    if not applicant_did or not applicant_did.startswith('did:pkh:solana:'):
        return jsonify({"error": "Invalid DID format"}), 400
    
    # 檢查DID是否已被使用
    existing_application = Application.query.filter_by(applicant_did=applicant_did).first()
    if existing_application and existing_application.id != application_id:
        return jsonify({"error": "DID already associated with another application"}), 400
    
    # 關聯DID
    application.applicant_did = applicant_did
    db.session.commit()
    
    return jsonify({"status": "success", "message": "DID successfully associated"})

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
    """憑證獲取頁面"""
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
        flash('憑證已發行，無法再次獲取', 'info')
        return redirect(url_for('public.application_status', application_id=application_id))
    
    # 生成獲取憑證的QR碼
    # 在實際項目中，這裡將包含預授權碼的數位皮夾URI
    credential_url = f"didholder://credential?pre_auth_code={credential.pre_auth_code}&issuer=fido.moi.gov.tw"
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(credential_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # 將圖片轉換為base64字符串
    buffered = io.BytesIO()
    img.save(buffered)
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('public/application_credential.html', 
                          application=application,
                          credential=credential,
                          qr_code=img_str,
                          credential_url=credential_url)

@bp.route('/application/lookup', methods=['GET', 'POST'])
def application_lookup():
    """申請查詢頁面"""
    if request.method == 'POST':
        application_id = request.form.get('application_id')
        if not application_id:
            flash('請輸入申請ID', 'danger')
            return render_template('public/application_lookup.html')
        
        return redirect(url_for('public.application_status', application_id=application_id))
    
    return render_template('public/application_lookup.html')