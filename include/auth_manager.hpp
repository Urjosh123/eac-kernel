#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

namespace auth_manager
{
	struct HardwareID
	{
		std::string smbios_uuid;
		std::string disk_serial;
		std::string mac_address;
	};

	bool GetHardwareID(HardwareID& out_hwid);
	bool VerifyLicense(const std::string& license_key);
	
	std::string GenerateHashedHWID(const HardwareID& hwid);
}
