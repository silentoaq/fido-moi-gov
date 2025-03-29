# 臺灣自然人憑證發行系統（Issuer）

這是基於去中心化身份（DID）和可驗證憑證（VC）技術開發的臺灣自然人憑證發行系統，遵循 OpenID for Verifiable Credential Issuance (OID4VCI) 標準。

## 系統功能

- 提供 did:web 格式的去中心化身份
- 支援 SD-JWT 格式的可驗證憑證
- 實現選擇性披露，保護用戶隱私
- 符合 OID4VCI 標準的憑證發行流程
- 管理員手動審核機制
- 憑證狀態查詢與撤銷功能

## 技術棧

- **Flask**: Web框架
- **SQLAlchemy**: ORM資料庫
- **PyJWT**: JWT處理
- **Cryptography**: 加密操作
- **Bootstrap 5**: 前端UI
- **QRCode.js**: QR碼生成

## 安裝與運行

### 環境需求

- Python 3.9+
- Windows 10 (可在其他平台上運行，但開發環境為Windows)

### 安裝步驟

1. 克隆本倉庫：
```
git clone [https://github.com/silentoaq/fido-moi-gov.git]
cd [fido-moi-gov]
```

2. 創建並激活虛擬環境：
```
conda create -n issuer python=3.11
conda activate issuer
```

3. 安裝依賴：
```
pip install -r requirements.txt
```

4. 初始化資料庫：
```
flask db init
flask db migrate -m "Initial migration."
flask db upgrade
```

5. 創建管理員帳號：
```
flask shell
>>> from app import db
>>> from app.models.user import User
>>> admin = User(username='admin', email='admin@example.com', is_admin=True)
>>> admin.set_password('password')
>>> db.session.add(admin)
>>> db.session.commit()
>>> exit()
```

6. 運行應用：
```
python run.py
```

## 系統架構

- **public**: 公開路由，處理DID文檔、憑證發行等
- **admin**: 管理員路由，處理申請審核、憑證管理等
- **models**: 數據模型，定義資料庫結構
- **utils**: 工具函數，處理JWT、DID等功能
- **templates**: 前端模板

## OID4VCI 端點

- **/.well-known/did.json**: DID 文檔端點
- **/.well-known/openid-credential-issuer**: 發行者元數據端點
- **/.well-known/jwks.json**: JSON Web Key Set 端點
- **/token**: 訪問令牌端點
- **/credential**: 憑證發行端點
- **/credential-status/{id}**: 憑證狀態端點

## 開發者

這是一個大學專題專案，由 [11110109] 開發。