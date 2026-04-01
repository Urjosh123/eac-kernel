#include "../include/utils.hpp"
#include <iostream>
#include <vector>
#include <Windows.h>
#include <Psapi.h>
#include <filesystem>
#include <fstream>

bool utils::FileExists(const std::string& path)
{
	return std::filesystem::exists(path);
}

uint64_t utils::GetKernelModuleBase(const std::string& module_name)
{
	LPVOID drivers[1024];
	DWORD cb_needed;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb_needed) && cb_needed < sizeof(drivers))
	{
		char sz_driver[1024];
		for (int i = 0; i < (cb_needed / sizeof(drivers[0])); i++)
		{
			if (GetDeviceDriverBaseNameA(drivers[i], sz_driver, sizeof(sz_driver)))
			{
				if (std::string(sz_driver).find(module_name) != std::string::npos)
				{
					return reinterpret_cast<uint64_t>(drivers[i]);
				}
			}
		}
	}

	return 0;
}

uint64_t utils::GetKernelExport(uint64_t module_base, const std::string& export_name)
{
	LPVOID drivers[1024];
	DWORD cb_needed;
	char module_path[MAX_PATH];

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb_needed) && cb_needed < sizeof(drivers))
	{
		for (int i = 0; i < (cb_needed / sizeof(drivers[0])); i++)
		{
			if (reinterpret_cast<uint64_t>(drivers[i]) == module_base)
			{
				GetDeviceDriverFileNameA(drivers[i], module_path, sizeof(module_path));
				break;
			}
		}
	}

	HMODULE local_module = LoadLibraryExA(module_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!local_module)
		return 0;

	uint64_t local_export = reinterpret_cast<uint64_t>(GetProcAddress(local_module, export_name.c_str()));
	if (!local_export)
	{
		FreeLibrary(local_module);
		return 0;
	}

	uint64_t offset = local_export - reinterpret_cast<uint64_t>(local_module);
	FreeLibrary(local_module);

	return module_base + offset;
}

bool utils::ReadFileToBuffer(const std::string& path, std::vector<uint8_t>& buffer)
{
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open())
		return false;

	file.seekg(0, std::ios::end);
	size_t size = file.tellg();
	file.seekg(0, std::ios::beg);

	buffer.assign(size, 0);
	file.read(reinterpret_cast<char*>(buffer.data()), size);
	file.close();

	return true;
}

uint64_t utils::PatternScan(uint64_t base, uint32_t size, const char* pattern, const char* mask)
{
	size_t pattern_length = strlen(mask);
	for (uint32_t i = 0; i < size - pattern_length; i++)
	{
		bool found = true;
		for (uint32_t j = 0; j < pattern_length; j++)
		{
			if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j))
			{
				found = false;
				break;
			}
		}
		if (found)
			return base + i;
	}
	return 0;
}

uint64_t utils::PatternScanMulti(uint64_t base, uint32_t size, const std::vector<Pattern>& patterns)
{
	for (const auto& pattern : patterns)
	{
		uint64_t res = PatternScan(base, size, pattern.pattern, pattern.mask);
		if (res != 0) return res;
	}
	return 0;
}

bool utils::ValidateDriverPE(const std::vector<uint8_t>& buffer)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer.data();
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;

	PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)(buffer.data() + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return false;

	if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
	if (nt_headers->OptionalHeader.SizeOfImage > 0x1000000) return false;

	return true;
}

bool utils::IsHVCIEnabled()
{
	HKEY h_key;
	DWORD hypervisor_enforced = 0;
	DWORD size = sizeof(DWORD);
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", 0, KEY_READ, &h_key) == ERROR_SUCCESS)
	{
		RegQueryValueExA(h_key, "Enabled", NULL, NULL, (LPBYTE)&hypervisor_enforced, &size);
		RegCloseKey(h_key);
	}
	return (hypervisor_enforced != 0);
}

bool utils::IsSecureBootEnabled()
{
	DWORD secure_boot = 0;
	DWORD size = sizeof(DWORD);
	return (secure_boot != 0);
}
