import os
import sys
import click
import uuid
import logging
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import json
import base64

from flask.cli import FlaskGroup
from app import create_app, db
from app.models import Admin, Application, Credential, DIDCommSession

app = create_app()
cli = FlaskGroup(create_app=create_app)

@cli.command('init-db')
@click.option('--force', is_flag=True, help='強制重新創建所有表')
def init_db(force):
    """初始化數據庫"""
    with app.app_context():
        if force:
            click.echo('正在刪除舊表...')
            db.drop_all()
        
        click.echo('正在創建數據庫表...')
        db.create_all()
        
        click.echo('檢查數據庫表是否存在...')
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()
        
        expected_tables = ['application', 'credential', 'didcomm_session', 'admin']
        missing_tables = [table for table in expected_tables if table not in existing_tables]
        
        if missing_tables:
            click.echo(f'警告：缺少以下表: {", ".join(missing_tables)}')
            click.echo('嘗試修復表結構...')
            # 嘗試修復缺少的表
            db.create_all()
            
            # 再次檢查
            inspector = db.inspect(db.engine)
            existing_tables = inspector.get_table_names()
            still_missing = [table for table in expected_tables if table not in existing_tables]
            
            if still_missing:
                click.echo(f'錯誤：仍然缺少表: {", ".join(still_missing)}')
                sys.exit(1)
            else:
                click.echo('表結構修復成功')
        
        click.echo('數據庫初始化完成。')

@cli.command('drop-db')
@click.confirmation_option(prompt='此操作將刪除所有數據，是否確定？')
def drop_db():
    """刪除數據庫中的所有數據"""
    with app.app_context():
        db.drop_all()
        click.echo('數據庫已重置。')

@cli.command('check-db')
def check_db():
    """檢查數據庫結構"""
    with app.app_context():
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        
        click.echo(f"發現 {len(tables)} 個表:")
        for table in tables:
            columns = [col['name'] for col in inspector.get_columns(table)]
            click.echo(f"- {table}: {', '.join(columns)}")

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
    did_path = os.path.join(app.root_path, '../.well-known/did.json')
    oid4vc_path = os.path.join(app.root_path, '../.well-known/openid-credential-issuer')
    
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
                "kid": "key-1"
            }
        ]
    }
    
    # 保存JWK
    with open(jwk_key_path, 'w') as f:
        json.dump(jwk, f, indent=2)
    
    # 生成DID文檔
    current_time = datetime.utcnow().isoformat() + 'Z'
    did_doc = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
        "https://w3id.org/sd-jwt/v1"
      ],
      "id": "did:web:fido.mov.gov",
      "verificationMethod": [
        {
          "id": "did:web:fido.mov.gov#key-1",
          "type": "JsonWebKey2020",
          "controller": "did:web:fido.mov.gov",
          "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_value,
            "kid": "key-1"
          }
        }
      ],
      "authentication": [
        "did:web:fido.mov.gov#key-1"
      ],
      "assertionMethod": [
        "did:web:fido.mov.gov#key-1"
      ],
      "service": [
        {
          "id": "did:web:fido.mov.gov#credential-service",
          "type": "CredentialService",
          "serviceEndpoint": "https://fido.mov.gov/api/v1/credentials"
        },
        {
          "id": "did:web:fido.mov.gov#status-service",
          "type": "CredentialStatusService",
          "serviceEndpoint": "https://fido.mov.gov/api/v1/credential-status"
        },
        {
          "id": "did:web:fido.mov.gov#verification-service",
          "type": "VerificationService",
          "serviceEndpoint": "https://fido.mov.gov/api/v1/verify"
        },
        {
          "id": "did:web:fido.mov.gov#oid4vci-service",
          "type": "OID4VCIService",
          "serviceEndpoint": "https://fido.mov.gov/.well-known/openid-credential-issuer"
        }
      ],
      "created": current_time,
      "updated": current_time
    }
    
    # 保存DID文檔
    with open(did_path, 'w') as f:
        json.dump(did_doc, f, indent=2)
    
    # 生成OID4VCI配置
    oid4vci_config = {
      "issuer": "https://fido.mov.gov",
      "credential_issuer": "https://fido.mov.gov",
      "authorization_server": "https://fido.mov.gov",
      "credential_endpoint": "https://fido.mov.gov/api/v1/credentials",
      "token_endpoint": "https://fido.mov.gov/api/v1/token",
      "jwks_uri": "https://fido.mov.gov/.well-known/jwks.json",
      "authorization_endpoint": "https://fido.mov.gov/api/v1/authorize",
      "grant_types_supported": [
        "authorization_code",
        "urn:ietf:params:oauth:grant-type:pre-authorized_code"
      ],
      "response_types_supported": [
        "code"
      ],
      "vp_formats_supported": {
        "jwt_sd": {
          "alg_values_supported": [
            "EdDSA"
          ]
        }
      },
      "credentials_supported": {
        "NaturalPersonCredential": {
          "format": "jwt_sd",
          "scope": "naturalPersonCredential",
          "cryptographic_binding_methods_supported": [
            "did:web",
            "did:pkh:solana"
          ],
          "cryptographic_suites_supported": [
            "Ed25519Signature2020"
          ],
          "credential_definition": {
            "type": [
              "VerifiableCredential",
              "NaturalPersonCredential"
            ],
            "credentialSubject": {
              "id": {
                "mandatory": True,
                "display": [
                  {
                    "name": "身分識別",
                    "locale": "zh-TW"
                  }
                ]
              },
              "name": {
                "mandatory": True,
                "display": [
                  {
                    "name": "姓名",
                    "locale": "zh-TW"
                  }
                ]
              },
              "birthDate": {
                "mandatory": True,
                "display": [
                  {
                    "name": "出生日期",
                    "locale": "zh-TW"
                  }
                ]
              },
              "gender": {
                "mandatory": True,
                "display": [
                  {
                    "name": "性別",
                    "locale": "zh-TW"
                  }
                ]
              },
              "address": {
                "mandatory": True,
                "display": [
                  {
                    "name": "戶籍地址",
                    "locale": "zh-TW"
                  }
                ]
              },
              "nationalIdNumber": {
                "mandatory": True,
                "display": [
                  {
                    "name": "身分證字號",
                    "locale": "zh-TW"
                  }
                ]
              }
            }
          },
          "proof_types_supported": [
            "Ed25519Signature2020"
          ]
        }
      },
      "display": [
        {
          "name": "內政部自然人憑證機構",
          "locale": "zh-TW",
          "logo": {
            "url": "https://fido.mov.gov/static/img/logo.png",
            "alt_text": "內政部標誌"
          },
          "description": "臺灣自然人憑證發行機構，提供個人身分數位驗證服務"
        }
      ]
    }
    
    # 保存OID4VCI配置
    with open(oid4vc_path, 'w') as f:
        json.dump(oid4vci_config, f, indent=2)
    
    click.echo('密鑰對生成成功，已保存以下文件:')
    click.echo(f'- 私鑰: {private_key_path}')
    click.echo(f'- 公鑰: {public_key_path}')
    click.echo(f'- JWK: {jwk_key_path}')
    click.echo(f'- DID文檔: {did_path}')
    click.echo(f'- OID4VCI配置: {oid4vc_path}')

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

@cli.group()
def test():
    """測試指令"""
    pass

@test.command('create-application')
def create_test_application():
    """創建測試申請記錄"""
    with app.app_context():
        app = Application(
            challenge=str(uuid.uuid4()),
            status='pending'
        )
        db.session.add(app)
        db.session.commit()
        click.echo(f'已創建測試申請記錄，ID: {app.id}')
        
@test.command('fake-did-auth')
@click.argument('application_id')
def fake_did_auth(application_id):
    """模擬DID身份驗證和數據提交"""
    with app.app_context():
        app = Application.query.get(application_id)
        if not app:
            click.echo(f'找不到申請 {application_id}')
            return
        
        app.applicant_did = f"did:pkh:solana:{uuid.uuid4()}"
        app.national_id = "A123456789"
        app.name = "測試用戶"
        app.birth_date = datetime.strptime("1990-01-01", "%Y-%m-%d").date()
        app.gender = "male"
        app.address = "台北市信義區市府路1號"
        app.birth_place = "台北市"
        app.status = "submitted"
        
        db.session.commit()
        click.echo(f'已模擬DID認證和數據提交，申請狀態更新為 {app.status}')
        click.echo(f'DID: {app.applicant_did}')

if __name__ == '__main__':
    cli()