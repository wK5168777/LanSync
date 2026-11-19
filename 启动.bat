@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>&1
if %errorlevel% neq 0 (
  echo ❌ 找不到 Python，请先安装 Python 3.10+ 并勾选 Add to PATH
  pause
  exit /b 1
)
echo 📦 检查依赖中...
python -c "import flask, flask_socketio" 2>nul
if %errorlevel% neq 0 (
  echo 📥 首次运行，正在安装依赖...
  python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
)
echo.
echo ================================================
echo   📡 LanSync · 局域网协同通讯台
echo ================================================
python app.py 5050
pause
