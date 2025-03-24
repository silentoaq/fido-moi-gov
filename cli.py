import os
import sys
import click
import uuid
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import json
import base64

from flask.cli import FlaskGroup
from app import create_app, db
from app.models import Admin, Application, Credential

app = create_app()
cli = FlaskGroup(create_app=create_app)

@cli.command('init-db')
def init_db():
    """初始化數據庫"""
    with app.app_context():
        db.create_all()
        click.echo('數據庫初始化完成。')

@cli.command('drop-db')
@click.confirmation_option(prompt='此操作將刪除所有數據，是否確定？')
def drop_db():
    """刪除數據庫中的所有數據"""
    with app.app_context():
        db.drop_all()
        click.echo('數據庫已重置。')

@cli.group()
def admin():
    """管理員相關命令"""
    pass

@admin.command('create')
@click.argument('username')
@click.option('--role', default='reviewer', help='角色: admin 或 reviewer')
@click.password_option(help='管理員密碼')
def create_admin(username, role, password):
    """創建新管理員"""
    with app.app_context():
        if Admin.query.filter_by(username=username).first():
            click.echo(f'管理員 {username} 已存在')
            return
        
        admin = Admin(username=username, role=role)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        click.echo(f'已創建管理員 {username}')

@admin.command('list')
def list_admins():
    """列出所有管理員"""
    with app.app_context():
        admins = Admin.query.all()
        if not admins:
            click.echo('尚無管理員')
            return
        
        click.echo(f"{'ID':<38} {'用戶名':<20} {'角色':<10} {'創建時間':<20}")
        click.echo('-' * 90)
        for admin in admins:
            created_at = admin.created_at.strftime('%Y-%m-%d %H:%M:%S')
            click.echo(f"{admin.id:<38} {admin.username:<20} {admin.role:<10} {created_at:<20}")

@admin.command('reset-password')
@click.argument('username')
@click.password_option(help='新密碼')
def reset_password(username, password):
    """重設管理員密碼"""
    with app.app_context():
        admin = Admin.query.filter_by(username=username).first()
        if not admin:
            click.echo(f'管理員 {username} 不存在')
            return
        
        admin.set_password(password)
        db.session.commit()
        click.echo(f'已重設 {username} 的密碼')

@cli.group()
def keys():
    """密鑰管理相關命令"""
    pass

@keys.command('generate')
@click.option('--force', is_flag=True, help='強制覆蓋現有密鑰')
def generate_keys(force):
    """生成新的Ed25519密鑰對"""
    private_key_path = os.path.join(app.root_path, '../keys/private.pem')
    public_key_path = os.path.join(app.root_path, '../keys/public.pem')
    jwk_key_path = os.path.join(app.root_path, '../.well-known/jwks.json')
    
    # 檢查目錄是否存在，不存在則創建
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
    os.makedirs(os.path.dirname(jwk_key_path), exist_ok=True)
    
    # 檢查文件是否已存在
    if os.path.exists(private_key_path) and not force:
        click.echo('密鑰文件已存在。使用 --force 參數來覆蓋。')
        return
    
    # 生成新的密鑰對
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # 保存私鑰
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, 'wb') as f:
        f.write(private_bytes)
    
    # 保存公鑰
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, 'wb') as f:
        f.write(public_bytes)
    
    # 生成JWK格式
    public_bytes_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    x_value = base64.urlsafe_b64encode(public_bytes_raw).decode('utf-8').rstrip('=')
    
    jwk = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x_value,
                "kid": "did-key-1"
            }
        ]
    }
    
    # 保存JWK
    with open(jwk_key_path, 'w') as f:
        json.dump(jwk, f, indent=2)
    
    click.echo('密鑰對生成成功，已保存私鑰、公鑰和JWK文件。')

@cli.group()
def credential():
    """憑證管理相關命令"""
    pass

@credential.command('list')
def list_credentials():
    """列出所有憑證"""
    with app.app_context():
        credentials = Credential.query.all()
        if not credentials:
            click.echo('尚無憑證')
            return
        
        click.echo(f"{'ID':<15} {'狀態':<10} {'申請ID':<38} {'發行時間':<20}")
        click.echo('-' * 85)
        for cred in credentials:
            issued_at = cred.issued_at.strftime('%Y-%m-%d %H:%M:%S') if cred.issued_at else 'N/A'
            click.echo(f"{cred.id[:13]:<15} {cred.status:<10} {cred.application_id:<38} {issued_at:<20}")

@credential.command('revoke')
@click.argument('credential_id')
def revoke_credential(credential_id):
    """撤銷指定憑證"""
    with app.app_context():
        cred = Credential.query.get(credential_id)
        if not cred:
            click.echo(f'憑證 {credential_id} 不存在')
            return
        
        cred.revoke()
        db.session.commit()
        click.echo(f'已撤銷憑證 {credential_id}')

@credential.command('cleanup')
def cleanup_expired():
    """清理過期的預授權碼"""
    with app.app_context():
        now = datetime.utcnow()
        expired_count = Credential.query.filter(
            Credential.code_expires_at < now,
            Credential.is_used == False
        ).update({'is_used': True})
        
        db.session.commit()
        click.echo(f'已清理 {expired_count} 個過期的預授權碼')

if __name__ == '__main__':
    cli()