@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo.
    echo   [错误] 未找到 python 命令。
    echo   请安装 Python 3 并在安装时勾选 "Add Python to PATH"。
    echo   下载: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

python -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo.
    echo   [错误] 当前 Python 缺少 tkinter,图形界面无法启动。
    echo   Windows 官方安装包默认自带 tkinter;若使用精简版请换标准安装包。
    echo.
    pause
    exit /b 1
)

python gui.py
if errorlevel 1 (
    echo.
    echo   程序异常退出,错误信息见上方。
    pause
)
endlocal
