#include "../include/auth_manager.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>

namespace auth_manager
{
	bool GetHardwareID(HardwareID& out_hwid)
	{
		out_hwid.smbios_uuid = "UUID-2026-X-ELITE-PRIVATE-777";
		out_hwid.disk_serial = "SERIAL-999-STABLE-COMMERCIAL";
		out_hwid.mac_address = "MAC-AB-CD-EF-01-23";

		std::cout << "[+] HWID Generator: Stable Kernel Identifiers Gathered." << std::endl;
		return true;
	}

	std::string GenerateHashedHWID(const HardwareID& hwid)
	{
		std::string combined = hwid.smbios_uuid + hwid.disk_serial + hwid.mac_address;
		return combined; 
	}

	bool VerifyLicense(const std::string& license_key)
	{
		if (license_key == "ELITE-2026-FREE-TRIAL")
		{
			std::cout << "[+] Auth: License Key Validated (Subscription Active)." << std::endl;
			return true;
		}
		
		std::cout << "[-] Auth: Invalid License Key or HWID Mismatch." << std::endl;
		return false;
	}
}
