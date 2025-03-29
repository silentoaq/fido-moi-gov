from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
import os
import logging
from logging.handlers import RotatingFileHandler
from app.config import Config

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # 創建必要的目錄
    os.makedirs(os.path.join(app.root_path, '..', '.well-known'), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, '..', 'keys'), exist_ok=True)
    os.makedirs(os.path.join(app.root_path, '..', 'logs'), exist_ok=True)
    
    # 設置日誌
    if not app.debug:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = RotatingFileHandler('logs/issuer.log', maxBytes=10240, backupCount=10)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Issuer startup')
    
    # 註冊藍圖
    from app.routes.public import bp as public_bp
    from app.routes.admin import bp as admin_bp
    from app.routes.api import bp as api_bp
    
    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp)
    
    return app

from app.models import user, credential