import os
from datetime import timedelta
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(os.path.dirname(basedir), '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URI') or \
        'sqlite:///' + os.path.join(basedir, '..', 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Issuer configuration
    ISSUER_HOST = os.environ.get('ISSUER_HOST') or 'twfido.ddns.net'
    ISSUER_PROTOCOL = os.environ.get('ISSUER_PROTOCOL') or 'https'
    
    # JWT configuration
    JWT_PRIVATE_KEY_PATH = os.environ.get('JWT_PRIVATE_KEY_PATH') or os.path.join(basedir, '..', 'keys', 'private.pem')
    JWT_PUBLIC_KEY_PATH = os.environ.get('JWT_PUBLIC_KEY_PATH') or os.path.join(basedir, '..', 'keys', 'public.pem')
    
    # Access token configuration
    ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Credential configuration
    CREDENTIAL_EXPIRES = timedelta(days=365)  # 1 year