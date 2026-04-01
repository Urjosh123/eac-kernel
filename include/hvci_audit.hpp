#pragma once
#include <string>
#include <vector>
#include <Windows.h>

namespace hvci_audit
{
	struct SlatEntry
	{
		uint64_t virtual_addr;
		uint64_t physical_addr;
		uint64_t entry_bits;
	};

	bool PerformGhostWalk(uintptr_t host_base, uint32_t host_size);
	uint64_t FindSlatBase();
	bool ValidateConsistency(uint64_t entry);
}
