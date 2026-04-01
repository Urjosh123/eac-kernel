#include <string>
#include <vector>
#include <Windows.h>
#include "../include/vad_utils.hpp"
#include "../include/intel_driver.hpp"
#include "../include/utils.hpp"

bool vad_utils::SpoofVAD(HANDLE iqvw64e_device_handle, uint64_t address, uint32_t size)
{
	uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
	if (ntoskrnl_base == 0) return false;

	uint64_t vad_root_ptr = utils::PatternScan(ntoskrnl_base, 0x1000000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x48\x18\x48\x8B\x01", "xxx????xxxxxxx");
	if (!vad_root_ptr) return false;

	uint32_t vad_flags = 0x1000000; 
	intel_driver::WriteMemory(iqvw64e_device_handle, address + 0x18, &vad_flags, sizeof(vad_flags)); 

	return true;
}
