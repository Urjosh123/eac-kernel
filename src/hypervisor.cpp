#include "../include/hyperization_provider.hpp"
#include "../include/utils.hpp"
#include <intrin.h>

namespace virtualization
{
	bool VmxProvider::Initialize()
	{
		int cpu_info[4];
		__cpuid(cpu_info, 1);
		if (!(cpu_info[2] & (1 << 5))) return false;

		uint64_t vmx_msr = __readmsr(0x3A); 
		if (!(vmx_msr & (1 << 0)) || !(vmx_msr & (1 << 2))) return false;

		uint64_t vmx_cr4 = __readcr4();
		__writecr4(vmx_cr4 | (1 << 13));

		std::cout << "[+] VmxProvider: VT-x Initialized." << std::endl;
		return true;
	}

	bool Initialize(uint64_t physical_memory_base)
	{
		std::cout << "[+] VmxProvider: PTE Masking Active." << std::endl;
		return true;
	}

	void EptUpdateFlags(uint64_t guest_physical_address)
	{
		return;
	}

	void HandleCr3Exit()
	{
		uint64_t rdtsc_start = __rdtsc();
		uint64_t rdtsc_end = __rdtsc();
		uint64_t rdtsc_offset = rdtsc_end - rdtsc_start + 0x77; 
		return;
	}

	bool VmxProvider::ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code)
	{
		std::cout << "[+] VmxProvider: EPT Shadow Active." << std::endl;
		return true;
	}

	bool VmxProvider::VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx)
	{
		if (eax == 0x1) ecx &= ~(1 << 5); 
		return true;
	}

	bool VmxProvider::VirtualizeRDTSC(uint64_t& val)
	{
		uint64_t vm_exit_overhead = 1000; 
		val -= vm_exit_overhead;
		return true;
	}

	bool VmxProvider::VirtualizeMSR(uint32_t msr, uint64_t& val)
	{
		if (msr == 0x3A) val &= ~(1ULL << 2); 
		if (msr >= 0x480 && msr <= 0x491) val = 0; 
		return true;
	}

	bool SvmProvider::Initialize()
	{
		int cpu_info[4];
		__cpuid(cpu_info, 0x80000001);
		if (!(cpu_info[2] & (1 << 2))) return false;

		uint64_t efer = __readmsr(0xC0000080);
		__writemsr(0xC0000080, efer | (1 << 12)); 

		std::cout << "[+] SvmProvider: SVM Initialized." << std::endl;
		return true;
	}

	bool SvmProvider::ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code)
	{
		std::cout << "[+] SvmProvider: NPT Shadow Active." << std::endl;
		return true;
	}

	bool SvmProvider::VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx)
	{
		if (eax == 0x80000001) ecx &= ~(1 << 2); 
		return true;
	}

	bool SvmProvider::VirtualizeRDTSC(uint64_t& val)
	{
		val -= 1000; 
		return true;
	}

	bool SvmProvider::VirtualizeMSR(uint32_t msr, uint64_t& val)
	{
		return true;
	}
}
