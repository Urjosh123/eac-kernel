@echo off
setlocal enabledelayedexpansion

:: Check for MSVC
where cl >nul 2>nul
if %errorlevel% neq 0 (
    echo [-] MSVC compiler (cl.exe) not found. Please run from Developer Command Prompt.
    pause
    exit /b
)

echo [+] Compiling mapper (Windows 10/11 20H2+)...

cl.exe /nologo /O2 /MT /W3 /std:c++17 /I./include ^
    src/main.cpp ^
    src/kdmapper.cpp ^
    src/intel_driver.cpp ^
    src/portable_executable.cpp ^
    src/utils.cpp ^
    /Fe:mapper.exe ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X64 Psapi.lib

if %errorlevel% equ 0 (
    echo [+] Build successful: mapper.exe
) else (
    echo [-] Build failed.
)

pause
