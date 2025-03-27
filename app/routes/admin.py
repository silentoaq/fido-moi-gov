import uuid
from datetime import datetime
from flask import Blueprint, request, render_template, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import Admin, Application, Credential

bp = Blueprint('admin', __name__, url_prefix='/admin')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """管理員登入頁面與處理"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            admin.update_last_login()
            db.session.commit()
            flash('登入成功', 'success')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('用戶名或密碼錯誤', 'danger')
    
    return render_template('admin/login.html')

@bp.route('/logout')
@login_required
def logout():
    """管理員登出"""
    logout_user()
    flash('已成功登出', 'success')
    return redirect(url_for('admin.login'))

@bp.route('/')
@bp.route('/dashboard')
@login_required
def dashboard():
    """管理員儀表板"""
    # 獲取統計資料
    pending_applications = Application.query.filter_by(status='pending').count()
    approved_applications = Application.query.filter_by(status='approved').count()
    valid_credentials = Credential.query.filter_by(status='valid').count()
    
    return render_template('admin/dashboard.html',
                          pending_applications=pending_applications,
                          approved_applications=approved_applications,
                          valid_credentials=valid_credentials)

@bp.route('/applications')
@login_required
def applications():
    """申請列表頁面"""
    status = request.args.get('status', 'all')
    
    # 根據狀態篩選
    if status == 'all':
        applications = Application.query.order_by(Application.created_at.desc()).all()
    else:
        applications = Application.query.filter_by(status=status).order_by(Application.created_at.desc()).all()
    
    return render_template('admin/applications.html', applications=applications, status=status)

@bp.route('/applications/<application_id>')
@login_required
def application_detail(application_id):
    """申請詳情頁面"""
    application = Application.query.get_or_404(application_id)
    return render_template('admin/application_detail.html', application=application)

@bp.route('/applications/<application_id>/approve', methods=['POST'])
@login_required
def approve_application(application_id):
    """批准申請"""
    application = Application.query.get_or_404(application_id)
    
    # 檢查是否可以批准
    if application.status != 'pending':
        flash('只能批准待處理的申請', 'danger')
        return redirect(url_for('admin.application_detail', application_id=application_id))
    
    # 檢查是否已關聯DID
    if not application.applicant_did:
        flash('申請尚未關聯DID，無法批准', 'danger')
        return redirect(url_for('admin.application_detail', application_id=application_id))
    
    # 更新申請狀態
    application.status = 'approved'
    application.reviewed_by = current_user.id
    application.review_notes = request.form.get('review_notes', '')
    
    # 創建憑證記錄
    credential = Credential(application_id=application.id)
    credential.generate_pre_auth_code()
    
    db.session.add(credential)
    db.session.commit()
    
    flash('申請已批准，憑證預授權碼已生成', 'success')
    return redirect(url_for('admin.application_detail', application_id=application_id))

@bp.route('/applications/<application_id>/reject', methods=['POST'])
@login_required
def reject_application(application_id):
    """拒絕申請"""
    application = Application.query.get_or_404(application_id)
    
    if application.status != 'pending':
        flash('只能拒絕待處理的申請', 'danger')
        return redirect(url_for('admin.application_detail', application_id=application_id))
    
    application.status = 'rejected'
    application.reviewed_by = current_user.id
    application.review_notes = request.form.get('review_notes', '')
    
    db.session.commit()
    
    flash('申請已拒絕', 'warning')
    return redirect(url_for('admin.application_detail', application_id=application_id))

@bp.route('/credentials')
@login_required
def credentials():
    """憑證列表頁面"""
    status = request.args.get('status', 'all')
    
    # 根據狀態篩選
    if status == 'all':
        credentials = Credential.query.order_by(Credential.created_at.desc()).all()
    else:
        credentials = Credential.query.filter_by(status=status).order_by(Credential.created_at.desc()).all()
    
    return render_template('admin/credentials.html', credentials=credentials, status=status)

@bp.route('/credentials/<credential_id>')
@login_required
def credential_detail(credential_id):
    """憑證詳情頁面"""
    credential = Credential.query.get_or_404(credential_id)
    application = Application.query.get(credential.application_id)
    
    return render_template('admin/credential_detail.html', credential=credential, application=application)

@bp.route('/credentials/<credential_id>/revoke', methods=['POST'])
@login_required
def revoke_credential(credential_id):
    """撤銷憑證"""
    credential = Credential.query.get_or_404(credential_id)
    
    if credential.status != 'valid':
        flash('只能撤銷有效的憑證', 'danger')
        return redirect(url_for('admin.credential_detail', credential_id=credential_id))
    
    # 撤銷憑證
    credential.revoke()
    db.session.commit()
    
    flash('憑證已撤銷', 'warning')
    return redirect(url_for('admin.credential_detail', credential_id=credential_id))

@bp.route('/credentials/<credential_id>/regenerate-code', methods=['POST'])
@login_required
def regenerate_code(credential_id):
    """重新生成預授權碼"""
    credential = Credential.query.get_or_404(credential_id)
    
    # 檢查是否可以重新生成
    if credential.status != 'valid' or credential.issued_at:
        flash('只能為尚未使用的有效憑證重新生成預授權碼', 'danger')
        return redirect(url_for('admin.credential_detail', credential_id=credential_id))
    
    # 重新生成預授權碼
    credential.generate_pre_auth_code()
    db.session.commit()
    
    flash('預授權碼已重新生成', 'success')
    return redirect(url_for('admin.credential_detail', credential_id=credential_id))