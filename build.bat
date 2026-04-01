@echo off
setlocal enabledelayedexpansion

:: 1. Search for MSVC environment
where cl >nul 2>nul
if %errorlevel% neq 0 (
    echo [+] MSVC not in PATH. Searching for local installation...
    
    set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
    if not exist "!VS_PATH!" set "VS_PATH=C:\Program Files (x86)\Microsoft Visual Studio\2022\Community"
    
    if exist "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" (
        echo [+] Found MSVC 2022 at !VS_PATH!. Configuring environment...
        call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
    ) else (
        echo [-] MSVC compiler (cl.exe) not found.
        echo [!] Please run this from a 'Developer Command Prompt' or install Visual Studio.
        pause
        exit /b
    )
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
    echo [-] Build failed. Check the errors above.
)

pause
