#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>
#include "../include/portable_executable.hpp"

bool portable_executable::LoadPEFile(const std::string& path, PEFile& pe_file)
{
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open())
		return false;

	file.seekg(0, std::ios::end);
	size_t size = file.tellg();
	file.seekg(0, std::ios::beg);

	pe_file.raw_data.assign(size, 0);
	file.read(reinterpret_cast<char*>(pe_file.raw_data.data()), size);
	file.close();

	PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(pe_file.raw_data.data());
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(pe_file.raw_data.data() + dos_header->e_lfanew);
	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
		return false;

	pe_file.nt_headers = *nt_headers;
	pe_file.image_base = nt_headers->OptionalHeader.ImageBase;
	pe_file.entry_point = nt_headers->OptionalHeader.AddressOfEntryPoint;
	pe_file.size_of_image = nt_headers->OptionalHeader.SizeOfImage;

	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
	for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		Section section;
		section.name = std::string(reinterpret_cast<const char*>(section_header[i].Name), 8);
		section.virtual_address = section_header[i].VirtualAddress;
		section.virtual_size = section_header[i].Misc.VirtualSize;
		section.raw_address = section_header[i].PointerToRawData;
		section.raw_size = section_header[i].SizeOfRawData;
		section.characteristics = section_header[i].Characteristics;
		
		section.data.assign(section.raw_size, 0);
		memcpy(section.data.data(), pe_file.raw_data.data() + section.raw_address, section.raw_size);

		pe_file.sections.push_back(section);
	}

	return true;
}
