#include <intrin.h>
#include <vector>
#include <string>
#include <Windows.h>
#include "../include/virtualization_provider.hpp"
#include "../include/utils.hpp"
#include "../include/hypervisor.hpp"

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

		uint64_t pin_controls;
		__vmx_vmread(0x4000, &pin_controls); 
		__vmx_vmwrite(0x4000, pin_controls | (1 << 3)); 

		return true;
	}

	typedef struct _EPT_ENTRY {
		uint64_t Read : 1;
		uint64_t Write : 1;
		uint64_t Execute : 1;
		uint64_t MemoryType : 3;
		uint64_t IgnorePat : 1;
		uint64_t PageSize : 1;
		uint64_t Accessed : 1;
		uint64_t Dirty : 1;
		uint64_t ExecUserMode : 1;
		uint64_t Reserved1 : 1;
		uint64_t PageFrameNumber : 40;
		uint64_t Reserved2 : 12;
	} EPT_ENTRY, *PEPT_ENTRY;

	bool Initialize(uint64_t physical_memory_base)
	{
		return true;
	}

	void EptUpdateFlags(uint64_t gpa, bool executable)
	{
		uint64_t eptp;
		__vmx_vmread(0x201A, &eptp); 
		
		PEPT_ENTRY pml4 = (PEPT_ENTRY)(eptp & ~0xFFFULL);
		PEPT_ENTRY pdpt = (PEPT_ENTRY)(pml4[(gpa >> 39) & 0x1FF].PageFrameNumber << 12);
		PEPT_ENTRY pd = (PEPT_ENTRY)(pdpt[(gpa >> 30) & 0x1FF].PageFrameNumber << 12);
		PEPT_ENTRY pt = (PEPT_ENTRY)(pd[(gpa >> 21) & 0x1FF].PageFrameNumber << 12);
		PEPT_ENTRY pte = &pt[(gpa >> 12) & 0x1FF];

		pte->Read = 1;
		pte->Write = 0;
		pte->Execute = executable ? 1 : 0;

		uint64_t pfn_db = utils::PatternScan(utils::GetKernelModuleBase("ntoskrnl.exe"), 0x1000000, "\x48\x8B\x05\x00\x00\x00\x00\x48\x8B\x40\x00\x48\x8B\x48\x00", "xxx????xxx?xxx?");
		if (pfn_db)
		{
			uint64_t pfn_index = gpa >> 12;
			uint64_t pfn_entry_addr = pfn_db + (pfn_index * 0x30); 
			EptUpdateFlags(pfn_entry_addr, false); 
		}
	}

	void HandleMtf()
	{
		uint64_t proc_controls;
		__vmx_vmread(0x4002, &proc_controls); 
		__vmx_vmwrite(0x4002, proc_controls & ~(1 << 27)); 
	}

	void HandleSplitPageAccess(uint64_t gpa, uint64_t rip)
	{
		uint64_t proc_controls;
		__vmx_vmread(0x4002, &proc_controls); 
		__vmx_vmwrite(0x4002, proc_controls | (1 << 27)); 
	}

	void HandleEptViolation(uint64_t gpa, uint64_t exit_qualification)
	{
		uint64_t rip;
		__vmx_vmread(0x681E, &rip); 

		if (((rip & 0xFFF) + 15) > 0x1000) 
		{
			HandleSplitPageAccess(gpa, rip);
			return;
		}
		
		return;
	}

	static uint64_t calibration_offset = 0;
	static uint64_t last_tsc = 0;

	void CalibrateTiming()
	{
		uint64_t total = 0;
		for (int i = 0; i < 10; i++)
		{
			uint64_t start = __rdtsc();
			__cpuidex(NULL, 0, 0); 
			uint64_t end = __rdtsc();
			total += (end - start);
		}
		calibration_offset = (total / 10) + 120; 
	}

	void HandleCr3Exit()
	{
		if (calibration_offset == 0) CalibrateTiming();
		
		uint64_t current = __rdtsc();
		last_tsc = current - calibration_offset;
		
		_mm_pause();
		return;
	}

	bool VmxProvider::ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code)
	{
		if (calibration_offset == 0) CalibrateTiming();

		for (uint32_t i = 0; i < size; i += 0x1000)
		{
			uint64_t gpa = (uint64_t)base + i;
			EptUpdateFlags(gpa, true); 
		}
		
		__vmx_vmlaunch(); 
		
		uint64_t current_eptp;
		__vmx_vmread(0x201A, &current_eptp);

		uint64_t invept_type = 1; 
		struct { uint64_t eptp; uint64_t reserved; } descriptor = { current_eptp, 0 };
		__vmx_invept(invept_type, &descriptor);

		return true;
	}

	bool VmxProvider::VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx)
	{
		int cpu_info[4];
		__cpuidex(cpu_info, eax, ecx);
		
		eax = cpu_info[0];
		ebx = cpu_info[1];
		ecx = cpu_info[2];
		edx = cpu_info[3];

		if (eax == 0x1) ecx &= ~(1 << 5); 
		return true;
	}

	bool VmxProvider::VirtualizeRDTSC(uint64_t& val)
	{
		uint64_t current = __rdtsc();
		uint32_t jitter = 0;
		_rdrand32_step(&jitter);
		jitter %= 20; 

		val = current - calibration_offset + jitter;
		
		if (val <= last_tsc) val = last_tsc + 1;
		last_tsc = val;

		return true;
	}

	bool VmxProvider::VirtualizeMSR(uint32_t msr, uint64_t& val)
	{
		if (msr == 0x3A) val &= ~(1ULL << 2); 
		if (msr >= 0x480 && msr <= 0x491) val = 0; 
		if (msr == 0x1A0) val |= (1ULL << 3); 
		return true;
	}

	bool SvmProvider::Initialize()
	{
		int cpu_info[4];
		__cpuid(cpu_info, 0x80000001);
		if (!(cpu_info[2] & (1 << 2))) return false;

		uint64_t efer = __readmsr(0xC0000080);
		__writemsr(0xC0000080, efer | (1 << 12)); 

		return true;
	}

	bool SvmProvider::ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code)
	{
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

	bool VmxProvider::MasterMode(uintptr_t gpa, bool executable)
	{
		uint64_t target_eptp;
		__vmx_vmread(0x201A, &target_eptp); 
		
		return true;
	}
}
