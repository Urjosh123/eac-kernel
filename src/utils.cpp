#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <Windows.h>
#include "../include/utils.hpp"

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

namespace utils
{
	bool FileExists(const std::string& path)
	{
		return std::filesystem::exists(path);
	}

	uint64_t GetKernelModuleBase(const std::string& module_name)
	{
		ULONG size = 0;
		NtQuerySystemInformation(11, NULL, 0, &size); 

		std::vector<uint8_t> buffer(size);
		if (NtQuerySystemInformation(11, buffer.data(), size, &size) != 0) return 0;

		PRTL_PROCESS_MODULES modules = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer.data());
		for (ULONG i = 0; i < modules->NumberOfModules; i++)
		{
			const char* name = reinterpret_cast<const char*>(modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName);
			if (module_name == name) return reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);
		}
		return 0;
	}

	uint64_t GetKernelExport(uint64_t module_base, const std::string& export_name)
	{
		std::string target_path = "C:\\Windows\\System32\\ntoskrnl.exe";
		std::vector<uint8_t> buffer;
		if (!utils::ReadFileToBuffer(target_path, buffer)) return 0;
		
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
		PIMAGE_NT_HEADERS64 nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.data() + dos_header->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(buffer.data() + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		
		uint32_t* names = reinterpret_cast<uint32_t*>(buffer.data() + export_dir->AddressOfNames);
		for (uint32_t i = 0; i < export_dir->NumberOfNames; i++)
		{
			const char* name = reinterpret_cast<const char*>(buffer.data() + names[i]);
			if (export_name == name)
			{
				uint16_t* ordinals = reinterpret_cast<uint16_t*>(buffer.data() + export_dir->AddressOfNameOrdinals);
				uint32_t* functions = reinterpret_cast<uint32_t*>(buffer.data() + export_dir->AddressOfFunctions);
				return module_base + functions[ordinals[i]];
			}
		}
		return 0;
	}

	bool ReadFileToBuffer(const std::string& path, std::vector<uint8_t>& buffer)
	{
		std::ifstream file(path, std::ios::binary);
		if (!file.is_open())
			return false;

		file.seekg(0, std::ios::end);
		size_t size = file.tellg();
		file.seekg(0, std::ios::beg);

		buffer.assign(size, 0);
		file.read(reinterpret_cast<char*>(buffer.data()), size);
		file.close();

		return true;
	}

	uint64_t PatternScan(uint64_t base, uint32_t size, const char* pattern, const char* mask)
	{
		size_t pattern_length = strlen(mask);
		for (uint32_t i = 0; i < size - pattern_length; i++)
		{
			bool found = true;
			for (uint32_t j = 0; j < pattern_length; j++)
			{
				if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j))
				{
					found = false;
					break;
				}
			}
			if (found)
				return base + i;
		}
		return 0;
	}

	uint64_t PatternScanMulti(uint64_t base, uint32_t size, const std::vector<Pattern>& patterns)
	{
		for (const auto& pattern : patterns)
		{
			uint64_t res = PatternScan(base, size, pattern.pattern, pattern.mask);
			if (res != 0) return res;
		}
		return 0;
	}

	bool ValidateDriverPE(const std::vector<uint8_t>& buffer)
	{
		PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer.data();
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;

		PIMAGE_NT_HEADERS64 nt_headers = (PIMAGE_NT_HEADERS64)(buffer.data() + dos_header->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return false;

		if (nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
		if (nt_headers->OptionalHeader.SizeOfImage > 0x1000000) return false;

		return true;
	}

	bool IsHVCIEnabled()
	{
		return false;
	}

	bool IsSecureBootEnabled()
	{
		return false;
	}
}
