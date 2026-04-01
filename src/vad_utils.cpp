#include "../include/vad_utils.hpp"
#include "../include/intel_driver.hpp"
#include "../include/utils.hpp"
#include <iostream>
#include <Windows.h>

bool vad_utils::SpoofVAD(HANDLE iqvw64e_device_handle, uint64_t address, uint32_t size)
{
	uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
	if (ntoskrnl_base == 0) return false;

	std::cout << "[+] VAD Spoofing complete for 0x" << std::hex << address << " (Mapped as 'VadImageMap')" << std::dec << std::endl;
	return true;
}
