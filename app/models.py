import uuid
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager

class Application(db.Model):
    """申請資料表"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    national_id = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    address = db.Column(db.Text, nullable=False)
    birth_place = db.Column(db.String(50), nullable=False)
    
    # DID 可能在申請時不存在，後續關聯
    applicant_did = db.Column(db.String(100), nullable=True)
    
    # 申請狀態
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    review_notes = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(36), db.ForeignKey('admin.id'), nullable=True)
    
    # 時間戳
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 關聯
    credentials = db.relationship('Credential', backref='application', lazy=True)

    def __repr__(self):
        return f'<Application {self.id}: {self.name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'national_id': self.national_id,
            'name': self.name,
            'birth_date': self.birth_date.isoformat() if self.birth_date else None,
            'gender': self.gender,
            'address': self.address,
            'birth_place': self.birth_place,
            'applicant_did': self.applicant_did,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

class Credential(db.Model):
    """憑證資料表"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    application_id = db.Column(db.String(36), db.ForeignKey('application.id'), nullable=False)
    credential_id = db.Column(db.String(64), unique=True, nullable=False, 
                             default=lambda: f"urn:uuid:{uuid.uuid4()}")
    
    # 預授權碼相關
    pre_auth_code = db.Column(db.String(64), unique=True, nullable=True)
    code_expires_at = db.Column(db.DateTime, nullable=True)
    is_used = db.Column(db.Boolean, default=False)
    
    # 憑證狀態
    status = db.Column(db.String(20), default='valid')  # valid, revoked
    issued_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    
    # 時間戳
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Credential {self.id}>'

    def generate_pre_auth_code(self):
        """生成預授權碼"""
        self.pre_auth_code = str(uuid.uuid4())
        self.code_expires_at = datetime.utcnow() + timedelta(hours=24)
        self.is_used = False
        return self.pre_auth_code

    def verify_pre_auth_code(self, code):
        """驗證預授權碼"""
        if (self.pre_auth_code == code and 
            self.code_expires_at > datetime.utcnow() and 
            not self.is_used):
            return True
        return False

    def mark_used(self):
        """標記預授權碼為已使用"""
        self.is_used = True

    def revoke(self):
        """撤銷憑證"""
        self.status = 'revoked'
        self.revoked_at = datetime.utcnow()

    def is_valid(self):
        """檢查憑證是否有效"""
        return (self.status == 'valid' and
                self.expires_at > datetime.utcnow())

class Admin(UserMixin, db.Model):
    """管理員資料表"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='reviewer')  # admin, reviewer
    
    # 時間戳
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<Admin {self.username}>'

    def set_password(self, password):
        """設置密碼"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """檢查密碼"""
        return check_password_hash(self.password_hash, password)

    def update_last_login(self):
        """更新最後登入時間"""
        self.last_login = datetime.utcnow()

@login_manager.user_loader
def load_user(user_id):
    """Flask-Login使用的用戶加載函數"""
    return Admin.query.get(user_id)