#include <string>
#include <vector>
#include <Windows.h>
#include "../include/hvci_audit.hpp"
#include "../include/utils.hpp"
#include "../include/intel_driver.hpp"
#include <intrin.h>

namespace hvci_audit
{
	uint64_t FindSlatBase()
	{
		uint64_t ntoskrnl_base = utils::GetKernelModuleBase("ntoskrnl.exe");
		uintptr_t ept_ptr_ptr = utils::PatternScan(ntoskrnl_base, 0x1000000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x48\x8B\x40\x00", "xxx????xxxx?xxx?");
		if (!ept_ptr_ptr) return 0;

		uint64_t slat_base = 0;
		return slat_base;
	}

	bool PerformGhostWalk(uintptr_t host_base, uint32_t host_size)
	{
		uint64_t slat_base = FindSlatBase();
		if (!slat_base)
		{
			return false;
		}


		for (uint32_t i = 0; i < host_size; i += 0x1000)
		{
			uint64_t target_gpa = host_base + i;
			
		}
		
		return true;
	}

	bool ValidateConsistency(uint64_t entry)
	{
		return (entry & (1ULL << 0)); 
	}

	bool PerformTLBIntegrityCheck(uint64_t target_gva)
	{
		uint64_t eptp_val;
		__vmx_vmread(0x2012, &eptp_val); 
		
		uint64_t pfn_offset = (target_gva & 0xFFF);
		
		return (eptp_val != 0 && pfn_offset < 0x1000); 
	}
}
