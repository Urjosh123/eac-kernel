#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace portable_executable
{
	struct Section
	{
		std::string name;
		uint32_t virtual_address;
		uint32_t virtual_size;
		uint32_t raw_address;
		uint32_t raw_size;
		uint32_t characteristics;
		std::vector<uint8_t> data;
	};

	struct PEFile
	{
		IMAGE_NT_HEADERS64 nt_headers;
		std::vector<Section> sections;
		std::vector<uint8_t> raw_data;
		uint64_t image_base;
		uint32_t entry_point;
		uint32_t size_of_image;
	};

	bool LoadPEFile(const std::string& path, PEFile& pe_file);
}
