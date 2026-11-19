@echo off
chcp 65001 >nul
echo ========================================================
echo   LanSync 开发环境恢复（给自己用的版本）
echo   · 重新打包 + 加回开发解锁文件（跳过硬件锁检查）
echo   · 你自己的电脑永远不会被锁
echo ========================================================
echo.

cd /d "%~dp0"

echo 📦 步骤 1/2：重新打包...
python -m PyInstaller --noconfirm LanSync.spec
if errorlevel 1 ( echo ❌ 打包失败 & pause & exit /b 1 )

echo.
echo ✅ 步骤 2/2：加回开发解锁文件...
if not exist dist\.lc_dev_unlock (
    echo. > dist\.lc_dev_unlock
    echo   已创建 dist\.lc_dev_unlock
) else (
    echo   dist\.lc_dev_unlock 已存在
)

echo.
echo 🧹 清理旧锁文件（调试用，不留旧绑定）...
del /f /q dist\.lc_lock 2>nul
del /f /q "%APPDATA%\LanSync.lock" 2>nul

echo.
echo ✅ 开发环境就绪！双击 dist\LanSync.exe 即可正常使用。
echo.
echo 🔑 开发解锁原理：
echo   dist\.lc_dev_unlock 空文件存在 → 启动时跳过硬件指纹检查
echo   没有这个文件 → 自动绑定当前电脑硬件，复制到别的电脑会拒绝
echo.
pause
