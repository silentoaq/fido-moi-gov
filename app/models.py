import uuid
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager

class Application(db.Model):
    """申請資料表"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # DIDComm 挑戰用於身份驗證
    challenge = db.Column(db.String(64), nullable=True, default=lambda: str(uuid.uuid4()))
    
    # 申請者DID，用戶通過數位皮夾關聯
    applicant_did = db.Column(db.String(100), nullable=True, index=True)
    
    # 個人資料，通過DIDComm從數位皮夾接收
    national_id = db.Column(db.String(10), nullable=True)  # 由用戶數位皮夾發送
    name = db.Column(db.String(50), nullable=True)  # 由用戶數位皮夾發送
    birth_date = db.Column(db.Date, nullable=True)  # 由用戶數位皮夾發送
    gender = db.Column(db.String(10), nullable=True)  # 由用戶數位皮夾發送
    address = db.Column(db.Text, nullable=True)  # 由用戶數位皮夾發送
    birth_place = db.Column(db.String(50), nullable=True)  # 由用戶數位皮夾發送
    
    # 申請狀態
    # pending: 初始狀態，等待用戶掃描QR碼並提交數據
    # submitted: 已通過DIDComm收到用戶數據，等待審核
    # approved: 已審核通過，可以發行憑證
    # rejected: 審核拒絕
    status = db.Column(db.String(20), default='pending')
    review_notes = db.Column(db.Text, nullable=True)
    reviewed_by = db.Column(db.String(36), db.ForeignKey('admin.id'), nullable=True)
    
    # 時間戳
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # 關聯
    credentials = db.relationship('Credential', backref='application', lazy=True)

    def __repr__(self):
        return f'<Application {self.id}: {self.name or "Pending"}>'

    def to_dict(self):
        """轉換為字典，用於API響應"""
        return {
            'id': self.id,
            'status': self.status,
            'applicant_did': self.applicant_did,
            'national_id': self.national_id,
            'name': self.name,
            'birth_date': self.birth_date.isoformat() if self.birth_date else None,
            'gender': self.gender,
            'address': self.address,
            'birth_place': self.birth_place,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def is_complete(self):
        """檢查申請是否包含所有必要的個人資料"""
        return (self.applicant_did and 
                self.national_id and 
                self.name and 
                self.birth_date and 
                self.gender and 
                self.address)
    
    def has_valid_did(self):
        """檢查是否有有效的DID"""
        return self.applicant_did and (
            self.applicant_did.startswith('did:pkh:solana:') or
            self.applicant_did.startswith('did:web:')
        )
    
    def update_status_if_complete(self):
        """如果申請資料完整，更新狀態為submitted"""
        if self.status == 'pending' and self.is_complete():
            self.status = 'submitted'
            return True
        return False
    
    def generate_new_challenge(self):
        """生成新的挑戰碼"""
        self.challenge = str(uuid.uuid4())
        return self.challenge

class Credential(db.Model):
    """憑證資料表"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    application_id = db.Column(db.String(36), db.ForeignKey('application.id'), nullable=False)
    credential_id = db.Column(db.String(64), unique=True, nullable=False, 
                             default=lambda: f"urn:uuid:{uuid.uuid4()}")
    
    # DIDComm交互識別碼，用於憑證發行過程中的消息關聯
    didcomm_thread_id = db.Column(db.String(64), nullable=True)
    
    # 預授權碼相關
    pre_auth_code = db.Column(db.String(64), unique=True, nullable=True)
    code_expires_at = db.Column(db.DateTime, nullable=True)
    is_used = db.Column(db.Boolean, default=False)
    
    # 憑證狀態
    status = db.Column(db.String(20), default='valid')  # valid, revoked
    issued_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    
    # 憑證內容 (SD-JWT)
    # 僅存儲必要的元數據，完整憑證通過DIDComm發送給持有者
    credential_type = db.Column(db.String(50), default='NaturalPersonCredential')
    issuer_did = db.Column(db.String(100), nullable=True)
    subject_did = db.Column(db.String(100), nullable=True)
    
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
                self.expires_at and
                self.expires_at > datetime.utcnow())
    
    def to_dict(self):
        """轉換為字典，用於API響應"""
        return {
            'id': self.id,
            'credential_id': self.credential_id,
            'status': self.status,
            'issued_at': self.issued_at.isoformat() if self.issued_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'credential_type': self.credential_type,
            'issuer_did': self.issuer_did,
            'subject_did': self.subject_did,
            'created_at': self.created_at.isoformat(),
        }

class DIDCommSession(db.Model):
    """DIDComm會話資料表，用於追蹤DIDComm消息交換"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # 相關申請或憑證ID
    application_id = db.Column(db.String(36), db.ForeignKey('application.id'), nullable=True)
    credential_id = db.Column(db.String(36), db.ForeignKey('credential.id'), nullable=True)
    
    # DIDComm消息標識符
    thread_id = db.Column(db.String(64), nullable=False)  # DIDComm消息thread ID
    from_did = db.Column(db.String(100), nullable=False)  # 發送者DID
    to_did = db.Column(db.String(100), nullable=False)    # 接收者DID
    
    # 會話狀態
    session_type = db.Column(db.String(20), nullable=False)  # auth, issuance, presentation
    status = db.Column(db.String(20), default='active')     # active, completed, failed
    
    # 挑戰碼和紀錄
    challenge = db.Column(db.String(64), nullable=True)
    last_message_id = db.Column(db.String(36), nullable=True)
    last_message_type = db.Column(db.String(100), nullable=True)
    
    # 時間戳和過期控制
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    def __repr__(self):
        return f'<DIDCommSession {self.id} {self.session_type}>'
    
    def is_active(self):
        """檢查會話是否有效"""
        if self.status != 'active':
            return False
        if self.expires_at and self.expires_at < datetime.utcnow():
            return False
        return True
    
    def complete(self):
        """標記會話為已完成"""
        self.status = 'completed'
    
    def fail(self, reason=None):
        """標記會話為失敗"""
        self.status = 'failed'
        # 可以記錄失敗原因到數據庫
    
    def add_message(self, message_id, message_type):
        """記錄最後一條消息"""
        self.last_message_id = message_id
        self.last_message_type = message_type
        self.updated_at = datetime.utcnow()

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