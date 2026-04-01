#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

namespace intel_driver
{
	struct COPY_MEMORY_BUFFER
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	};

	bool Load();
	bool Unload();
	bool IsLoaded();
	HANDLE Open();
	
	bool ReadMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size);
	bool WriteMemory(HANDLE iqvw64e_device_handle, uint64_t address, void* buffer, uint32_t size);
	
	uint64_t FindPteBase(uint64_t ntoskrnl_base);
	bool FlipExecuteBit(HANDLE iqvw64e_device_handle, uint64_t address, bool executable);
	bool ClearBigPoolTable(HANDLE iqvw64e_device_handle, uint64_t address);
	
	uint64_t CallKernelFunction(HANDLE iqvw64e_device_handle, uint64_t function_address, ...);
	
	uint64_t AllocatePool(HANDLE iqvw64e_device_handle, uint32_t size, uint32_t tag = 'mdkd');
	bool FreePool(HANDLE iqvw64e_device_handle, uint64_t address);
	
	uint64_t FindPiDDBLock(uint64_t ntoskrnl_base);
	uint64_t FindPiDDBCacheTable(uint64_t ntoskrnl_base);
	bool ClearPiDDBCacheTable(HANDLE iqvw64e_device_handle);
	bool ClearMmUnloadedDrivers(HANDLE iqvw64e_device_handle);
}
