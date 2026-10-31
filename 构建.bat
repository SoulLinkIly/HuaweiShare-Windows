@echo off
chcp 65001 >nul
title 华为分享 - 构建
cd /d "%~dp0"


echo [1/3] cargo build --release --no-default-features
cargo build --release --no-default-features --bin hwshare --manifest-path "%~dp0src\Cargo.toml"
if errorlevel 1 goto fail

echo.
echo [2/3] cargo test --release --no-default-features --lib
cargo test --release --no-default-features --lib --quiet --manifest-path "%~dp0src\Cargo.toml"
if errorlevel 1 goto fail

echo.
echo [3/3] 生成 华为分享.exe
copy /y "%~dp0src\target\release\hwshare.exe" "%~dp0华为分享.exe" >nul
certutil -hashfile "%~dp0华为分享.exe" SHA256 | findstr /v ":"
echo.
echo 完成：双击 华为分享.exe 即可运行。
pause
exit /b 0

:fail
echo.
echo 构建失败，看上面的报错。
pause
exit /b 1
