# KDmapper-style Kernel Driver Mapper (20H2+ Optimized)

This is a highly optimized, stealthy manual mapper for Windows kernel drivers (64-bit). It bypasses Driver Signature Enforcement (DSE) by exploiting a vulnerable signed driver.

## Features
- **Project Structure**: Cleanly organized into `include/` and `src/` directories.
- **Manual Mapping**: Loads driver image into kernel pool, resolves imports and relocations in user-mode.
- **Windows Support**: Optimized for Windows 10/11 version 20H2 and newer.
- **Stealth**: 
    - **Physical Memory Hijacking**: Option to map code into legitimate driver sections (`--hijack`).
    - **AVL Tree Unlinking**: Clears `PiDDBCacheTable` entry for the vulnerable driver.
    - **MmUnloadedDrivers Wiping**: Wipes entry from the kernel's unloaded drivers history.
    - **Full PE Scrubbing**: Wipes `MZ`, `PE` headers, and section tables for zero signature-based trace.

## Requirements
- **Vulnerable Driver**: You need `iqvw64e.sys` (Intel Network Adapter Diagnostics).
- **Windows Version**: Windows 10/11 64-bit (20H2 or later).
- **Compiler**: Visual Studio C++17.

## Usage
1. Open Developer Command Prompt.
2. Run `build.bat`.
3. Standard: `mapper.exe your_driver.sys`
4. **Stealth**: `mapper.exe your_driver.sys --hijack`

## Anti-Cheat Evasion Check List
1. [x] **No Module List Entry**: The driver is mapped without being added to `PsLoadedModuleList`.
2. [x] **No Unloaded Driver Entry**: Wipes traces from `MmUnloadedDrivers` (Optimized for 20H2+).
3. [x] **No Cache Entry**: Cleans `PiDDBCacheTable`.
4. [x] **No PE Signature**: Full scrubbing of `MZ`, `PE`, and section headers.
5. [!] **Threadless Execution**: Do not create your own system threads.
6. [!] **Communication Stealth**: Use a shared memory or stolen IOCTL, avoid `IoCreateDevice`.

---
**Disclaimer**: This tool is for educational and authorized testing purposes only.
