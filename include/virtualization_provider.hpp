#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace virtualization
{
	class Provider
	{
	public:
		virtual bool Initialize() = 0;
		virtual bool ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code) = 0;
		virtual bool VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx) = 0;
		virtual bool VirtualizeRDTSC(uint64_t& val) = 0;
		virtual bool VirtualizeMSR(uint32_t msr, uint64_t& val) = 0;
	};

	class VmxProvider : public Provider
	{
	public:
		bool Initialize() override;
		bool ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code) override;
		bool VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx) override;
		bool VirtualizeRDTSC(uint64_t& val) override;
		bool VirtualizeMSR(uint32_t msr, uint64_t& val) override;
		bool MasterMode(uintptr_t gpa, bool executable);
	};

	class SvmProvider : public Provider
	{
	public:
		bool Initialize() override;
		bool ShadowModule(uintptr_t base, uint32_t size, uint8_t* actual_code, uint8_t* clean_code) override;
		bool VirtualizeCPUID(uint32_t& eax, uint32_t& ebx, uint32_t& ecx, uint32_t& edx) override;
		bool VirtualizeRDTSC(uint64_t& val) override;
		bool VirtualizeMSR(uint32_t msr, uint64_t& val) override;
	};
}
