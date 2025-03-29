from flask import Blueprint, render_template, redirect, url_for, request, flash, session, current_app
from functools import wraps
from app import db
from app.models.user import User
from app.models.credential import Application, Credential, PreAuthCode
from app.utils.jwt import generate_pre_auth_code
from datetime import datetime

bp = Blueprint('admin', __name__)

def admin_required(f):
    """確保只有管理員可以訪問"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            flash('請先登入管理員帳號', 'warning')
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """管理員登入"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username, is_admin=True).first()
        if user and user.check_password(password):
            session['admin_logged_in'] = True
            session['admin_id'] = user.id
            next_page = request.args.get('next')
            flash('登入成功', 'success')
            return redirect(next_page or url_for('admin.dashboard'))
        
        flash('登入失敗，請檢查帳號密碼', 'danger')
    
    return render_template('admin/login.html')

@bp.route('/logout')
def logout():
    """管理員登出"""
    session.pop('admin_logged_in', None)
    session.pop('admin_id', None)
    flash('您已成功登出', 'info')
    return redirect(url_for('admin.login'))

@bp.route('/dashboard')
@admin_required
def dashboard():
    """管理員儀表板"""
    # 獲取統計數據
    total_applications = Application.query.count()
    pending_applications = Application.query.filter_by(status='pending').count()
    approved_applications = Application.query.filter_by(status='approved').count()
    issued_credentials = Credential.query.count()
    revoked_credentials = Credential.query.filter_by(is_revoked=True).count()
    
    stats = {
        'total_applications': total_applications,
        'pending_applications': pending_applications,
        'approved_applications': approved_applications,
        'issued_credentials': issued_credentials,
        'revoked_credentials': revoked_credentials
    }
    
    # 最近的申請
    recent_applications = Application.query.order_by(Application.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats, recent_applications=recent_applications)

@bp.route('/applications')
@admin_required
def applications():
    """申請列表"""
    # 獲取過濾參數
    status = request.args.get('status', 'all')
    page = request.args.get('page', 1, type=int)
    
    # 構建查詢
    query = Application.query
    
    if status != 'all':
        query = query.filter_by(status=status)
    
    # 分頁
    applications = query.order_by(Application.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    return render_template('admin/applications.html', applications=applications, current_status=status)

@bp.route('/applications/<application_id>')
@admin_required
def application_detail(application_id):
    """申請詳情"""
    application = Application.query.get_or_404(application_id)
    from datetime import datetime
    # 傳入當前時間用於模板中判斷預授權碼是否過期
    return render_template('admin/application_detail.html', application=application, now=datetime.utcnow())

@bp.route('/applications/<application_id>/review', methods=['POST'])
@admin_required
def application_review(application_id):
    """審核申請"""
    application = Application.query.get_or_404(application_id)
    
    if application.status != 'pending':
        flash('此申請已被審核，無法重複審核', 'warning')
        return redirect(url_for('admin.application_detail', application_id=application_id))
    
    decision = request.form.get('decision')
    comment = request.form.get('comment', '')
    
    if decision not in ['approve', 'reject']:
        flash('無效的審核決定', 'danger')
        return redirect(url_for('admin.application_detail', application_id=application_id))
    
    # 更新申請狀態
    if decision == 'approve':
        application.status = 'approved'
        application.approved_at = datetime.utcnow()
        
        # 生成新的預授權碼用於憑證領取
        new_code, expires_at = generate_pre_auth_code()
        pre_auth = PreAuthCode(
            code=new_code,
            application_id=application.id,
            expires_at=expires_at
        )
        db.session.add(pre_auth)
        
        flash('申請已核准，用戶可以領取憑證', 'success')
    else:
        application.status = 'rejected'
        flash('申請已拒絕', 'warning')
    
    application.reviewer_comment = comment
    db.session.commit()
    
    return redirect(url_for('admin.applications'))

@bp.route('/issued-credentials')
@admin_required
def issued_credentials():
    """已發行憑證列表"""
    page = request.args.get('page', 1, type=int)
    is_revoked = request.args.get('revoked', 'false') == 'true'
    
    query = Credential.query.filter_by(is_revoked=is_revoked)
    credentials = query.order_by(Credential.issued_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    
    from datetime import datetime
    return render_template('admin/issued_credentials.html', credentials=credentials, is_revoked=is_revoked, now=datetime.utcnow())

@bp.route('/revoke-credential/<credential_id>', methods=['POST'])
@admin_required
def revoke_credential(credential_id):
    """撤銷憑證"""
    credential = Credential.query.get_or_404(credential_id)
    
    if credential.is_revoked:
        flash('此憑證已被撤銷', 'warning')
        return redirect(url_for('admin.issued_credentials'))
    
    reason = request.form.get('reason', '')
    credential.is_revoked = True
    credential.revocation_reason = reason
    
    db.session.commit()
    
    flash('憑證已撤銷', 'success')
    return redirect(url_for('admin.issued_credentials'))



@bp.route('/manage-users')
@admin_required
def manage_users():
    """管理使用者"""
    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@bp.route('/add-user', methods=['GET', 'POST'])
@admin_required
def add_user():
    """添加使用者"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        is_admin = 'is_admin' in request.form
        
        # 檢查使用者是否已存在
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('使用者名稱或電子郵件已存在', 'danger')
            return redirect(url_for('admin.add_user'))
        
        user = User(username=username, email=email, is_admin=is_admin)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('使用者已成功添加', 'success')
        return redirect(url_for('admin.manage_users'))
    
    return render_template('admin/add_user.html')

@bp.route('/edit-user/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    """編輯用戶"""
    user = User.query.get_or_404(user_id)
    
    # 獲取表單數據
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    is_admin = 'is_admin' in request.form
    
    # 檢查用戶名和郵箱唯一性
    existing_user = User.query.filter(
        (User.username == username) | (User.email == email),
        User.id != user_id
    ).first()
    
    if existing_user:
        flash('用戶名或電子郵件已被其他用戶使用', 'danger')
        return redirect(url_for('admin.manage_users'))
    
    # 更新用戶信息
    user.username = username
    user.email = email
    if password:
        user.set_password(password)
    user.is_admin = is_admin
    
    db.session.commit()
    
    flash('用戶信息已更新', 'success')
    return redirect(url_for('admin.manage_users'))

@bp.route('/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """刪除用戶"""
    # 防止刪除當前登入的用戶
    if session.get('admin_id') == user_id:
        flash('不能刪除當前登入的用戶', 'danger')
        return redirect(url_for('admin.manage_users'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    
    flash('用戶已刪除', 'success')
    return redirect(url_for('admin.manage_users'))