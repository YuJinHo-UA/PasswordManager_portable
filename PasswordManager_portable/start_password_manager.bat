@echo off
chcp 65001 >nul
title 🔐 Password Manager Launcher
color 0A

echo ========================================
echo    🔐 ЗАПУСК МЕНЕДЖЕРА ПАРОЛЕЙ
echo ========================================
echo.

:: Проверка наличия Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Python не найден!
    echo.
    echo Установи Python с python.org
    echo.
    pause
    exit /b
)

echo ✅ Python найден
echo.

:: Проверка наличия зависимостей
echo 🔍 Проверка зависимостей...

python -c "import customtkinter" 2>nul
if %errorlevel% neq 0 (
    echo ❌ Не найден модуль customtkinter
    echo.
    echo Установи: pip install customtkinter
    echo.
    pause
    exit /b
)

python -c "import cryptography" 2>nul
if %errorlevel% neq 0 (
    echo ❌ Не найден модуль cryptography
    echo.
    echo Установи: pip install cryptography
    echo.
    pause
    exit /b
)

python -c "import pyperclip" 2>nul
if %errorlevel% neq 0 (
    echo ⚠️ Модуль pyperclip не найден
    echo Программа будет работать, но копирование в буфер может не работать
    echo.
    echo Установи: pip install pyperclip
    echo.
    choice /c YN /m "Продолжить?"
    if errorlevel 2 exit /b
)

echo ✅ Все зависимости найдены
echo.

:: Запуск программы
echo 🚀 Запуск менеджера паролей...
echo.

start /B python main.py

if %errorlevel% equ 0 (
    echo ✅ Программа запущена
) else (
    echo ❌ Ошибка запуска
    echo.
    pause
    exit /b
)

echo.
echo ========================================
echo    🔐 МЕНЕДЖЕР ПАРОЛЕЙ ЗАПУЩЕН
echo ========================================
echo.
echo 📁 Папка: %CD%
echo.
echo ⚡ Для выхода закрой окно программы
echo.
pause