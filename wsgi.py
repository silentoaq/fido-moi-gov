from waitress import serve
from app import create_app
import os
import logging

# 設置日誌
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/waitress.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('waitress')

# 創建Flask應用
app = create_app()

if __name__ == '__main__':
    # 獲取環境變數或使用預設值
    host = os.environ.get('ISSUER_HOST_IP', '0.0.0.0')
    port = int(os.environ.get('ISSUER_PORT', 5000))
    threads = int(os.environ.get('WAITRESS_THREADS', 4))
    
    logger.info(f'啟動應用於 {host}:{port}，使用 {threads} 個線程')
    
    # 使用Waitress啟動應用
    serve(app, host=host, port=port, threads=threads)