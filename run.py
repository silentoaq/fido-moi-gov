import os
from app import create_app
import ssl

app = create_app()

# SSL 證書路徑
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'certs')
CERT_FILE = os.path.join(CERT_DIR, 'cert.pem')
KEY_FILE = os.path.join(CERT_DIR, 'key.pem')

# 確保證書目錄存在
if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)

# 檢查證書文件是否存在
if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
    print("警告: SSL證書文件未找到。請使用以下命令生成:")
    print("  mkdir -p certs")
    print("  mkcert -install")
    print("  mkcert -cert-file certs/cert.pem -key-file certs/key.pem fido.moi.gov.tw localhost 127.0.0.1 ::1")
    print("將以HTTP模式啟動。")
    
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=5000, debug=True)
else:
    # 創建SSL上下文
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)
    
    # 強制所有請求使用HTTPS
    @app.before_request
    def enforce_https():
        from flask import request, redirect
        if request.scheme != 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)
    
    if __name__ == '__main__':
        print(f"以HTTPS模式啟動服務器在 https://fido.moi.gov.tw:5000")
        app.run(host='0.0.0.0', port=5000, ssl_context=context, debug=True)