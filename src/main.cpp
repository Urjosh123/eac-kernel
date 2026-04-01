#include <string>
#include <vector>
#include <Windows.h>

#include "../include/intel_driver.hpp"
#include "../include/portable_executable.hpp"
#include "../include/utils.hpp"
#include "../include/kdmapper.hpp"

int main(int argc, char* argv[])
{
	if (argc < 2) return 1;

	std::string p = argv[1];
	bool h = (argc > 3); 

	std::vector<uint8_t> b;
	if (!utils::ReadFileToBuffer(p, b)) return 2;

	if (!intel_driver::IsLoaded()) {
		if (!intel_driver::Load()) {
			return -1;
		}
	}

	HANDLE h_dev = intel_driver::Open();
	if (h_dev == INVALID_HANDLE_VALUE)
	{
		intel_driver::Unload();
		return -1;
	}

	if (!kdmapper::MapDriver(h_dev, p, h))
	{
		intel_driver::Unload();
		return 5;
	}

	intel_driver::Unload();
	return 0;
}
