import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(test_config=None):
    # 創建和配置應用
    app = Flask(__name__, instance_relative_config=True)
    
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev'),
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.instance_path, 'fido.sqlite'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    if test_config is None:
        # 如果不是測試，讀取配置文件
        app.config.from_pyfile('config.py', silent=True)
    else:
        # 如果是測試，加載測試配置
        app.config.from_mapping(test_config)

    # 確保實例文件夾存在
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
    # 初始化擴展
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    login_manager.login_view = 'admin.login'
    login_manager.login_message = '請先登入'
    
    # 註冊藍圖
    from app.routes import admin, public, oid4vci
    app.register_blueprint(admin.bp)
    app.register_blueprint(public.bp)
    app.register_blueprint(oid4vci.bp)
    
    # 註冊well-known路由
    @app.route('/.well-known/openid-credential-issuer')
    def well_known_credential_issuer():
        # 返回發證機構配置
        with open(os.path.join(app.root_path, '../.well-known/openid-credential-issuer'), 'r') as f:
            content = f.read()
        return app.response_class(
            response=content,
            mimetype='application/json'
        )
    
    @app.route('/.well-known/jwks.json')
    def well_known_jwks():
        # 返回公鑰配置
        with open(os.path.join(app.root_path, '../.well-known/jwks.json'), 'r') as f:
            content = f.read()
        return app.response_class(
            response=content,
            mimetype='application/json'
        )
    
    @app.route('/.well-known/did.json')
    def well_known_did():
        # 返回DID文檔
        with open(os.path.join(app.root_path, '../.well-known/did.json'), 'r') as f:
            content = f.read()
        return app.response_class(
            response=content,
            mimetype='application/json'
        )
    
    return app