@echo off
setlocal enabledelayedexpansion

echo [+] Searching for Visual Studio...

:: 1. Is cl.exe already in path?
where cl >nul 2>nul
if %errorlevel% equ 0 goto :BUILD

:: 2. Aggressive Search for vswhere.exe
set "VSWHERE_PATHS="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" "%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe""
for %%P in (%VSWHERE_PATHS%) do (
    if exist %%P (
        for /f "usebackq tokens=*" %%i in (`%%P -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_INSTALL_PATH=%%i"
    )
)

if defined VS_INSTALL_PATH (
    echo [+] Found Installation at: %VS_INSTALL_PATH%
    if exist "%VS_INSTALL_PATH%\VC\Auxiliary\Build\vcvars64.bat" (
        call "%VS_INSTALL_PATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
        goto :BUILD
    )
)

echo [-] ERROR: MSVC compiler not found.
echo ---------------------------------------------------------
echo 1. Open 'Visual Studio Installer'
echo 2. Click 'Modify'
echo 3. Ensure 'Desktop development with C++' is CHECKED.
echo ---------------------------------------------------------
pause
exit /b

:BUILD
echo [+] Compiling mapper...

cl.exe /nologo /O2 /MT /W3 /EHsc /std:c++17 /I./include ^
    src/main.cpp ^
    src/kdmapper.cpp ^
    src/intel_driver.cpp ^
    src/portable_executable.cpp ^
    src/utils.cpp ^
    src/vad_utils.cpp ^
    src/parasite_utils.cpp ^
    /Fe:mapper.exe ^
    /link /SUBSYSTEM:CONSOLE /MACHINE:X64 Psapi.lib ntdll.lib Advapi32.lib

if %errorlevel% equ 0 (
    echo [+] Build successful: mapper.exe
) else (
    echo [-] Build failed. Review the errors above.
)
pause
