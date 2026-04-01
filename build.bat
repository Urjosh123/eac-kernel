@echo off

:: 1. Is cl.exe already in path?
where cl >nul 2>nul
if %errorlevel% equ 0 goto :BUILD

:: 2. Try using vswhere
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VS_INSTALL_PATH=%%i"
    if defined VS_INSTALL_PATH (
        if exist "%VS_INSTALL_PATH%\VC\Auxiliary\Build\vcvars64.bat" (
            call "%VS_INSTALL_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
            goto :BUILD
        )
    )
)

echo [-] MSVC compiler not found.
echo [!] Please run this from a 'Developer Command Prompt' or install C++ build tools in Visual Studio.
pause
exit /b

:BUILD
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
