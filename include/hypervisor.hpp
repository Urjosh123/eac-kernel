#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace virtualization
{
	struct VMCS
	{
		uint64_t ghost_vmcs_ptr;
		uint64_t actual_vmcs_ptr;
	};

	bool InitializeVT();
	bool TakeControl();
	bool ReleaseControl();
	
	bool ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code);
	
	bool VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx);
	bool VirtualizeMSR(uint32_t msr, uint64_t& val);
}
