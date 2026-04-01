#include "../include/service_utils.hpp"
#include <iostream>
#include <Windows.h>

bool service_utils::ServiceManager::RegisterDriver(const std::string& service_name, const std::string& driver_path)
{
	SC_HANDLE sc_manager = ::OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (!sc_manager) return false;

	SC_HANDLE service = ::CreateServiceA(sc_manager, service_name.c_str(), service_name.c_str(), SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_path.c_str(), NULL, NULL, NULL, NULL, NULL);
	
	if (!service)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			service = ::OpenServiceA(sc_manager, service_name.c_str(), SERVICE_ALL_ACCESS);
		}
	}

	if (!service)
	{
		::CloseServiceHandle(sc_manager);
		return false;
	}

	::CloseServiceHandle(service);
	::CloseServiceHandle(sc_manager);
	return true;
}

bool service_utils::ServiceManager::RunDriver(const std::string& service_name)
{
	SC_HANDLE sc_manager = ::OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
	if (!sc_manager) return false;

	SC_HANDLE service = ::OpenServiceA(sc_manager, service_name.c_str(), SERVICE_START);
	if (!service)
	{
		::CloseServiceHandle(sc_manager);
		return false;
	}

	bool success = ::StartServiceA(service, 0, NULL) || ::GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
	::CloseServiceHandle(service);
	::CloseServiceHandle(sc_manager);
	return success;
}

bool service_utils::ServiceManager::HaltDriver(const std::string& service_name)
{
	SC_HANDLE sc_manager = ::OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
	if (!sc_manager) return false;

	SC_HANDLE service = ::OpenServiceA(sc_manager, service_name.c_str(), SERVICE_STOP);
	if (!service)
	{
		::CloseServiceHandle(sc_manager);
		return false;
	}

	SERVICE_STATUS status;
	bool success = ::ControlService(service, SERVICE_CONTROL_STOP, &status);
	::CloseServiceHandle(service);
	::CloseServiceHandle(sc_manager);
	return success;
}

bool service_utils::ServiceManager::DeleteDriver(const std::string& service_name)
{
	SC_HANDLE sc_manager = ::OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
	if (!sc_manager) return false;

	SC_HANDLE service = ::OpenServiceA(sc_manager, service_name.c_str(), DELETE);
	if (!service)
	{
		::CloseServiceHandle(sc_manager);
		return false;
	}

	bool success = ::DeleteService(service);
	::CloseServiceHandle(service);
	::CloseServiceHandle(sc_manager);
	return success;
}
