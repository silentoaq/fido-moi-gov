import os
from datetime import timedelta

class Config:
    """應用程式基本配置"""
    # 安全設置
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-please-change-in-production'
    
    # 數據庫配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), '../instance/fido.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 憑證配置
    CREDENTIAL_VALIDITY_DAYS = 365  # 憑證有效期（天）
    PRE_AUTH_CODE_EXPIRY_HOURS = 24  # 預授權碼有效期（小時）
    ACCESS_TOKEN_EXPIRY_MINUTES = 5  # 訪問令牌有效期（分鐘）
    
    # 發行者設置
    ISSUER_DID = 'did:web:fido.mov.gov'
    ISSUER_KID = 'did:web:fido.mov.gov#key-1'
    
    # 文件路徑
    KEY_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), '../keys')
    PRIVATE_KEY_PATH = os.path.join(KEY_DIR, 'private.pem')
    PUBLIC_KEY_PATH = os.path.join(KEY_DIR, 'public.pem')
    
    # 允許的憑證類型
    SUPPORTED_CREDENTIAL_TYPES = ['NaturalPersonCredential']

    # CORS設置 - 允許所有域的API和.well-known請求
    CORS_ORIGINS = ['*']

class DevelopmentConfig(Config):
    """開發環境配置"""
    DEBUG = True
    

class TestingConfig(Config):
    """測試環境配置"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


class ProductionConfig(Config):
    """生產環境配置"""
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get('SECRET_KEY')  # 必須在環境變量中設置
    
    # 生產環境資料庫URL
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    
    # 生產環境應啟用HTTPS
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True


# 根據環境變量載入配置
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}