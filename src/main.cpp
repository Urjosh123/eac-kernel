#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

#include "../include/intel_driver.hpp"
#include "../include/portable_executable.hpp"
#include "../include/utils.hpp"
#include "../include/kdmapper.hpp"

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		std::cout << "[-] Usage: mapper.exe <driver.sys> [--hijack]" << std::endl;
		return -1;
	}

	std::string driver_path = argv[1];
	bool use_hijack = false;
	if (argc > 2 && std::string(argv[2]) == "--hijack")
		use_hijack = true;

	if (!utils::FileExists(driver_path))
	{
		std::cout << "[-] Driver file not found: " << driver_path << std::endl;
		return -1;
	}

	std::cout << "[+] Loading vulnerable driver..." << std::endl;
	
	if (!intel_driver::IsLoaded()) {
		if (!intel_driver::Load()) {
			std::cout << "[-] Failed to load vulnerable driver" << std::endl;
			return -1;
		}
	}

	std::cout << "[+] Mapping driver..." << std::endl;

	HANDLE iqvw64e_device_handle = intel_driver::Open();
	if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] Failed to open handle to vulnerable driver" << std::endl;
		intel_driver::Unload();
		return -1;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle, driver_path, use_hijack))
	{
		std::cout << "[-] Failed to map driver" << std::endl;
		intel_driver::Unload();
		return -1;
	}

	std::cout << "[+] Driver mapped successfully. Cleaning up..." << std::endl;

	intel_driver::Unload();

	std::cout << "[+] Finished!" << std::endl;

	return 0;
}
