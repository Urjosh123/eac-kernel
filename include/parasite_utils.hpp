#pragma once
#include <iostream>
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

	bool FindHostModule(uint32_t min_size, HostModule& out_host);
	bool HijackPhysicalMemory(HANDLE iqvw64e_device_handle, uintptr_t host_base, uint8_t* payload, uint32_t size);
}
