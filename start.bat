@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================================
echo ⚡ Đang khởi động NetPulse (Webhook Inspector ^& Fuzzer)...
echo 🌐 Mở trình duyệt tại: http://localhost:4080
echo ========================================================
start "" "http://localhost:4080"
node server.js
pause

