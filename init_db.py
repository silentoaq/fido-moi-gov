"""
數據庫初始化腳本
用於創建初始數據庫和管理員用戶
"""
import os
import sys
import getpass
from dotenv import load_dotenv
from flask import Flask
from flask_migrate import Migrate

# 加載環境變量
load_dotenv()

# 確保工作目錄正確
current_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(current_dir)

def create_app():
    """創建應用實例"""
    app = Flask(__name__)
    
    # 加載配置
    app.config.from_object('app.config.Config')
    
    # 初始化數據庫
    from app import db
    db.init_app(app)
    
    # 初始化遷移
    migrate = Migrate()
    migrate.init_app(app, db)
    
    return app

def init_database(app):
    """初始化數據庫"""
    from app import db
    from flask_migrate import upgrade
    
    with app.app_context():
        # 創建所有表
        db.create_all()
        print("數據庫表已創建")
        
        # 運行遷移
        try:
            upgrade()
            print("遷移已應用")
        except Exception as e:
            print(f"遷移失敗，但這可能是正常的如果是首次運行: {e}")

def create_admin_user(app):
    """創建管理員用戶"""
    from app import db
    from app.models.user import User
    
    with app.app_context():
        # 檢查是否已有管理員
        existing_admin = User.query.filter_by(is_admin=True).first()
        if existing_admin:
            print(f"管理員用戶已存在: {existing_admin.username}")
            if input("是否創建新的管理員用戶? (y/n): ").lower() != 'y':
                return
        
        # 收集用戶信息
        username = input("請輸入管理員用戶名: ")
        email = input("請輸入管理員電子郵件: ")
        password = getpass.getpass("請輸入管理員密碼: ")
        confirm_password = getpass.getpass("請再次輸入密碼確認: ")
        
        if password != confirm_password:
            print("密碼不匹配，請重試")
            return
        
        # 創建用戶
        admin = User(username=username, email=email, is_admin=True)
        admin.set_password(password)
        
        try:
            db.session.add(admin)
            db.session.commit()
            print(f"管理員用戶 '{username}' 已成功創建")
        except Exception as e:
            db.session.rollback()
            print(f"創建用戶失敗: {e}")

def check_environment():
    """檢查環境變量和依賴項"""
    required_vars = ['SECRET_KEY', 'ISSUER_HOST', 'ISSUER_PROTOCOL']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"警告: 以下環境變量未設置: {', '.join(missing_vars)}")
        if input("是否繼續? (y/n): ").lower() != 'y':
            sys.exit(1)
    
    try:
        import jwt
        import cryptography
        import waitress
    except ImportError as e:
        print(f"錯誤: 缺少必要的依賴項: {e}")
        print("請先運行 'pip install -r requirements.txt'")
        sys.exit(1)

def ensure_directories():
    """確保必要的目錄存在"""
    directories = ['logs', 'keys', '.well-known']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"已確保目錄存在: {directory}")

def main():
    """主函數"""
    print("=== 臺灣自然人憑證發行系統初始化 ===")
    
    # 檢查環境
    check_environment()
    
    # 確保目錄存在
    ensure_directories()
    
    # 創建應用
    app = create_app()
    
    # 初始化數據庫
    init_database(app)
    
    # 創建管理員用戶
    create_admin_user(app)
    
    print("=== 初始化完成 ===")
    print("您現在可以運行 'python wsgi.py' 啟動應用")

if __name__ == "__main__":
    main()