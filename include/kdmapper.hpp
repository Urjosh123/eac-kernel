#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

#include "intel_driver.hpp"
#include "portable_executable.hpp"

namespace kdmapper
{
	bool MapDriver(HANDLE iqvw64e_device_handle, const std::string& driver_path, bool hijack = false);
	uint64_t FindHijackTarget(HANDLE iqvw64e_device_handle, uint32_t size);
	bool Relocate(uint8_t* raw_image, uint64_t target_base, uint64_t source_base);
	bool ResolveImports(HANDLE iqvw64e_device_handle, uint8_t* raw_image);
}
