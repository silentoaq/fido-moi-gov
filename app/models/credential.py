from app import db
from datetime import datetime
import uuid

class Application(db.Model):
    """申請記錄模型"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    holder_did = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    national_id = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending, approved, rejected, issued
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    reviewer_comment = db.Column(db.Text)
    pre_auth_code = db.Column(db.String(100))
    credential_id = db.Column(db.String(100))
    
    def __repr__(self):
        return f'<Application {self.id} - {self.name}>'

class PreAuthCode(db.Model):
    """預授權碼模型"""
    code = db.Column(db.String(100), primary_key=True)
    application_id = db.Column(db.String(36), db.ForeignKey('application.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    application = db.relationship('Application', backref=db.backref('pre_auth_codes', lazy=True))
    
    def __repr__(self):
        return f'<PreAuthCode {self.code}>'

class AccessToken(db.Model):
    """訪問令牌模型"""
    token = db.Column(db.String(255), primary_key=True)
    pre_auth_code = db.Column(db.String(100), db.ForeignKey('pre_auth_code.code'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    
    pre_auth = db.relationship('PreAuthCode', backref=db.backref('access_tokens', lazy=True))
    
    def __repr__(self):
        return f'<AccessToken {self.token[:10]}...>'

class Credential(db.Model):
    """憑證模型"""
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    application_id = db.Column(db.String(36), db.ForeignKey('application.id'), nullable=False)
    holder_did = db.Column(db.String(100), nullable=False)
    sd_jwt = db.Column(db.Text, nullable=False)
    disclosures = db.Column(db.JSON, nullable=False)
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)
    revocation_reason = db.Column(db.Text)
    
    application = db.relationship('Application', backref=db.backref('credential', uselist=False))
    
    def __repr__(self):
        return f'<Credential {self.id} - {self.holder_did}>'