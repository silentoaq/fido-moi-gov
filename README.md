
# 系統架構與發行流程

## 系統環境
- Windows

## 技術棧
- **後端**：Python 3.11 + Flask + Jinja2（用於 Issuer 部分）
- **伺服器**：Nginx（反向代理和 HTTPS）
- **安全**：OpenSSL（生成自簽名憑證）
- **通訊協議**：DIDComm（用於安全通訊）
- **憑證發行協議**：自定義的 OID4VCI 實現，結合 DIDComm 進行通訊
- **VC 格式**：SD-JWT（Selective Disclosure JSON Web Token）
- **網域設置**：通過修改 `C:\Windows\System32\drivers\etc\hosts` 設置網域

## 發行流程
1. 用戶通過數位皮夾向 Issuer 發送憑證請求（包含 DID 和簽名），使用 DIDComm。
2. Issuer 驗證簽名，生成 SD-JWT 格式的 VC（包含所有屬性和選擇性披露選項）。
3. Issuer 通過 DIDComm 將 VC 傳回數位皮夾。
