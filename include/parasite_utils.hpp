#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace parasite_utils
{
	struct HostModule
	{
		std::string name;
		uintptr_t base;
		uint32_t size;
	};

	bool FindHostModule(uint32_t size, HostModule& host);
	bool HijackPhysicalMemory(HANDLE iqvw64e_device_handle, uint64_t target_base, uint8_t* payload, uint32_t size);
	bool RestoreHost(HANDLE iqvw64e_device_handle, uint64_t target_base, uint8_t* original_data, uint32_t size);
}
