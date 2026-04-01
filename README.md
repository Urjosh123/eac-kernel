# eac-kernel

Simple kernel manual mapper for x64 drivers. Bypasses DSE via `iqvw64e.sys` exploitation.

### Usage
Run from a developer command prompt:
1. `build.bat`
2. `mapper.exe <driver.sys> [--hijack]`

### Features
*   **Manual Mapping**: Resolves relocations and imports in user-mode.
*   **Hijack Mode**: Maps into legitimate sections of `dxgkrnl.sys`.
*   **Cleanup**: Wipes `PiDDBCacheTable`, `MmUnloadedDrivers`, and `PoolBigPageTable` entries.
*   **Scrubbing**: Full header and metadata zercing (0x1000 bytes).
*   **Safety**: Page-alignment and HVCI detection.

### Requirements
*   `iqvw64e.sys` must be in the same directory.
*   Windows 10/11 (20H2 or later).
*   MSVC (cl.exe).
