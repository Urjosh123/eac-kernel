#pragma once
#include <Windows.h>

namespace vad_utils
{
	struct MMVAD_FLAGS
	{
		uint32_t VadType : 3;
		uint32_t Protection : 5;
		uint32_t PreferredNode : 6;
		uint32_t NoChange : 1;
		uint32_t PrivateMemory : 1;
		uint32_t ReadOnly : 1;
		uint32_t Enclave : 1;
		uint32_t ShadowStack : 1;
		uint32_t Spare : 13;
	};

	bool SpoofVAD(HANDLE iqvw64e_device_handle, uint64_t address, uint32_t size);
}
