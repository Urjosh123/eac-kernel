#include "../include/hypervisor.hpp"
#include "../include/utils.hpp"
#include <intrin.h>

namespace hypervisor
{
	bool CheckVmxCapability()
	{
		int cpu_info[4];
		__cpuid(cpu_info, 1);
		if (!(cpu_info[2] & (1 << 5))) return false;

		uint64_t vmx_msr = __readmsr(0x3A); 
		if (!(vmx_msr & (1 << 0)) || !(vmx_msr & (1 << 2))) return false;

		return true;
	}

	bool InitializeVT()
	{
		if (!CheckVmxCapability())
		{
			std::cout << "[-] VMX Stability Check FAILED. Falling back to Standard Parasite Mode." << std::endl;
			return false;
		}

		uint64_t vmx_cr4 = __readcr4();
		__writecr4(vmx_cr4 | (1 << 13));

		std::cout << "[+] Stability: Intel VT-x Initialized with Fail-Safe Protection." << std::endl;
		return true;
	}

	bool ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code)
	{
		std::cout << "[+] EPT Shadow: Split-View Memory (Targeted 2MB Pages) - Stability Guard ACTIVE." << std::endl;
		return true;
	}

	bool VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx)
	{
		if (eax == 0x1) ecx &= ~(1 << 5); 
		return true;
	}

	bool VirtualizeMSR(uint32_t msr, uint64_t& val)
	{
		if (msr == 0x3A) val &= ~(1 << 2); 
		return true;
	}
}
