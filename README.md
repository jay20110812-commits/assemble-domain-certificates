# 依域名合成 TLS 證書

這個 Codex skill 讀取 PEM、CRT、CER、KEY、PFX、P12 或 ZIP 檔，依憑證的 DNS SAN 名稱建立各自的資料夾。每個資料夾輸出 `<域名>.key` 與 `fullchain.crt`；主域名與 `www` 名稱分開處理。處理前會核對憑證與私鑰是否匹配，遇到不同的既有輸出時預設停止。

## 安裝

將 `skills/assemble-domain-certificates`、`skills/cert`、`skills/cert-path` 複製到 `~/.codex/skills/`。如需 `/prompts:cert` 與 `/prompts:cert_path` 快捷指令，另將 `prompts/*.md` 複製到 `~/.codex/prompts/`，並重新開啟 Codex 對話。

## 使用

先指定輸出位置，再處理檔案：

```text
/prompts:cert_path /absolute/path/to/cert_store
/prompts:cert /absolute/path/to/certificate.zip
```

也可以在 Codex 中呼叫 `$cert-path`、`$cert`，或直接執行：

```bash
python3 skills/assemble-domain-certificates/scripts/assemble.py --set-output /absolute/path/to/cert_store
python3 skills/assemble-domain-certificates/scripts/assemble.py /absolute/path/to/certificate.zip
```

需要 OpenSSL。若輸入 PFX 或私鑰有密碼，使用 `--password-env` 指定裝有密碼的環境變數。腳本不會將私鑰內容輸出到終端。

此 repository 不包含範例憑證、私鑰或個人的輸出路徑設定。
