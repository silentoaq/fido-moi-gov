from datetime import datetime
from flask import Blueprint, jsonify, request, current_app
from app.models.credential import Credential
import json

bp = Blueprint('api', __name__)

@bp.route('/api/health')
def health_check():
    """健康檢查端點，用於監控系統狀態"""
    try:
        # 檢查數據庫連接
        from app import db
        db.session.execute('SELECT 1')
        
        # 檢查基本功能
        from app.utils.crypto import get_public_key_jwk
        jwk = get_public_key_jwk()
        
        return jsonify({
            "status": "ok",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "services": {
                "database": "up",
                "crypto": "up"
            }
        })
    except Exception as e:
        current_app.logger.error(f"健康檢查失敗: {str(e)}")
        return jsonify({
            "status": "error",
            "timestamp": datetime.utcnow().isoformat(),
            "message": str(e)
        }), 500

@bp.route('/api/credential-status/<credential_id>')
def api_credential_status(credential_id):
    """API端點：憑證狀態檢查"""
    credential = Credential.query.get(credential_id)
    
    if not credential:
        return jsonify({
            "active": False,
            "reason": "credential_not_found"
        })
    
    status = {
        "active": not credential.is_revoked and credential.expires_at > datetime.utcnow(),
        "id": credential.id,
        "issued_at": credential.issued_at.isoformat(),
        "expires_at": credential.expires_at.isoformat()
    }
    
    if credential.is_revoked:
        status["reason"] = "revoked"
        status["revocation_reason"] = credential.revocation_reason
    elif credential.expires_at <= datetime.utcnow():
        status["reason"] = "expired"
    
    return jsonify(status)