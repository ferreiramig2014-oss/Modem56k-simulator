@echo off
title Instalador Virtual Modem 56kbps
setlocal enabledelayedexpansion

echo.
echo  =====================================================
echo   Instalador Virtual Fax/Modem 56kbps para COM10
echo  =====================================================
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERRO] Execute como Administrador!
    pause & exit /b 1
)

echo [1/3] Verificando Python...
set "PYCMD="
py --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PYCMD=py"
    echo  [OK] Python encontrado via: py
    goto :pyok
)
python --version >nul 2>&1
if %errorlevel% equ 0 (
    set "PYCMD=python"
    echo  [OK] Python encontrado via: python
    goto :pyok
)
echo  [ERRO] Python nao encontrado. Instale em https://python.org
pause & exit /b 1
:pyok
%PYCMD% --version
echo.

echo [2/3] Instalando pyserial...
%PYCMD% -m pip install pyserial --quiet
echo  pyserial OK.
echo.

echo [3/3] Verificando portas COM10 e COM11...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "if (Get-WmiObject Win32_SerialPort | Where-Object { $_.DeviceID -eq 'COM10' }) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] COM10 encontrada.
) else (
    echo  [AVISO] COM10 nao encontrada! Tentando criar par via com0com...
    if exist "C:\Program Files\com0com\setupc.exe" (
        "C:\Program Files\com0com\setupc.exe" install PortName=COM10 PortName=COM11
        echo  [OK] Par COM10^<->COM11 criado!
    ) else if exist "C:\Program Files (x86)\com0com\setupc.exe" (
        "C:\Program Files (x86)\com0com\setupc.exe" install PortName=COM10 PortName=COM11
        echo  [OK] Par COM10^<->COM11 criado!
    ) else (
        echo  [ERRO] com0com nao instalado! Baixe em:
        echo         https://com0com.sourceforge.net/
        echo  Instale o com0com, crie o par COM10^<->COM11 e rode este bat novamente.
        pause & exit /b 1
    )
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "if (Get-WmiObject Win32_SerialPort | Where-Object { $_.DeviceID -eq 'COM11' }) { exit 0 } else { exit 1 }" >nul 2>&1
if %errorlevel% equ 0 (
    echo  [OK] COM11 encontrada.
) else (
    echo  [ERRO] COM11 nao encontrada mesmo apos tentar criar o par!
    echo  Abra o com0com Setup manualmente e crie: COM10 ^<-^> COM11
    pause & exit /b 1
)
echo.

echo  =====================================================
echo   Tudo pronto!
echo.
echo   1. Rode: py modem56k_sim.py
echo   2. rasphone ^> nova conexao discada
echo      ^> Modem: Modem Padrao de 56000 bps ^> COM10
echo  =====================================================
echo.
pause
