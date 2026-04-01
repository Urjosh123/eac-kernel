#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace wnf_bridge
{
	typedef struct _WNF_STATE_NAME {
		ULONG Data[2];
	} WNF_STATE_NAME, *PWNF_STATE_NAME;

	bool Initialize();
	bool SendCommand(uint32_t cmd, uint64_t data);
	bool ReceiveResponse(uint64_t& data);
	
	bool Execute(uint64_t function_address, uint64_t rcx);
	bool ClearWnfTraces();
}
