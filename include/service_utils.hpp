#pragma once
#include <string>
#include <Windows.h>

namespace service_utils
{
	class ServiceManager
	{
	public:
		static bool RegisterDriver(const std::string& service_name, const std::string& driver_path);
		static bool RunDriver(const std::string& service_name);
		static bool HaltDriver(const std::string& service_name);
		static bool DeleteDriver(const std::string& service_name);
	};
}
