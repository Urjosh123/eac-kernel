#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include <Psapi.h>

namespace utils
{
	bool FileExists(const std::string& path);
	uint64_t GetKernelModuleBase(const std::string& module_name);
	uint64_t GetKernelExport(uint64_t module_base, const std::string& export_name);
	bool ReadFileToBuffer(const std::string& path, std::vector<uint8_t>& buffer);
	uint64_t PatternScan(uint64_t base, uint32_t size, const char* pattern, const char* mask);
	bool ValidateDriverPE(const std::vector<uint8_t>& buffer);
	bool IsHVCIEnabled();
	bool IsSecureBootEnabled();
}
