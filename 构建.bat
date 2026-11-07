@echo off
chcp 65001 >nul
cd /d "%~dp0src"
powershell -NoProfile -ExecutionPolicy Bypass -File ".\build.ps1" %*
if errorlevel 1 (
    echo.
    echo [失败] 构建未通过，请检查上面的错误。
) else (
    echo.
    echo [完成] 图形界面 ..\bin\hwshare.exe
    echo        命令行   ..\bin\hwshare-cli.exe
)
pause
