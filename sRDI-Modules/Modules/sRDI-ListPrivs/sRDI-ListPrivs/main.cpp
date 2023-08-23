#define no_init_all
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <strsafe.h>

DWORD threadID;

BOOL CheckPrivilege(HANDLE hToken, LPCWSTR priv)
{
	/* Checks for Privilege and returns True or False. */
	LUID luid;
	PRIVILEGE_SET privs;

	if (!LookupPrivilegeValueW(NULL, priv, &luid))
	{
		return FALSE;
	}

	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	BOOL bResult = FALSE;
	PrivilegeCheck(hToken, &privs, &bResult);
	return bResult;
}

// ref: https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege
BOOL SetPrivilege(
	HANDLE& hToken,          // access token handle
	LPCWSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValueW(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))          // receives LUID of privilege
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return FALSE;
	}

	return TRUE;
}

// TODO.
BOOL ListPrivs(const HANDLE& hToken, std::wstring* result)
{
	// https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants#constants
	std::vector<std::wstring> list = { L"SeAssignPrimaryTokenPrivilege",
		L"SeAuditPrivilege", L"SeBackupPrivilege",
		L"SeChangeNotifyPrivilege", L"SeCreateGlobalPrivilege",
		L"SeCreatePagefilePrivilege", L"SeCreatePermanentPrivilege",
		L"SeCreateSymbolicLinkPrivilege",
		L"SeCreateTokenPrivilege", L"SeDebugPrivilege",
		L"SeEnableDelegationPrivilege",
		L"SeImpersonatePrivilege", L"SeIncreaseBasePriorityPrivilege",
		L"SeIncreaseQuotaPrivilege",
		L"SeIncreaseWorkingSetPrivilege", L"SeLoadDriverPrivilege", L"SeLockMemoryPrivilege",
		L"SeMachineAccountPrivilege", L"SeManageVolumePrivilege", L"SeProfileSingleProcessPrivilege",
		L"SeRelabelPrivilege", L"SeRemoteShutdownPrivilege", L"SeRestorePrivilege", L"SeSecurityPrivilege",
		L"SeShutdownPrivilege", L"SeSyncAgentPrivilege", L"SeSystemEnvironmentPrivilege",
		L"SeSystemProfilePrivilege", L"SeSystemtimePrivilege", L"SeTakeOwnershipPrivilege",
		L"SeTcbPrivilege", L"SeTimeZonePrivilege", L"SeTrustedCredManAccessPrivilege",
		L"SeUndockPrivilege", L"SeUnsolicitedInputPrivilege" };

	std::wstring myresult = L"";

	for (size_t i = 0; i < list.size(); i++)
	{
		// TODO
		// Use CheckPrivilege to determine the status.
		//
		// BOOL CheckPrivilege(HANDLE hToken, LPCWSTR priv)
		//....
		BOOL status = CheckPrivilege(hToken, list[i].c_str());
		std::wstring item = list[i];
		item.append(L": ");
		item.append(status? L"TRUE": L"FALSE");
		item.append(L"\n");
		myresult.append(item);
	}

	*result = myresult;
	myresult.clear();

	return TRUE;
}

BOOL SetPrivs(HANDLE& hProcess, LPCWSTR priv, BOOL enabled = TRUE)
{
	HANDLE hToken;
	BOOL bRet = FALSE;

	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (SetPrivilege(hToken, priv, enabled))
		{
			bRet = TRUE;
		}

		CloseHandle(hToken);
	}

	return bRet;
}

extern "C" __declspec(dllexport) LPWSTR ExecuteW(LPCWSTR lpUserdata, DWORD nUserdataLen)
{
	UNREFERENCED_PARAMETER(lpUserdata);
	UNREFERENCED_PARAMETER(nUserdataLen);

	LPWSTR result = NULL;
	HRESULT hr = E_FAIL;
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken = NULL;

	OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
	if (hToken == NULL)
	{
		return NULL;
	}

	std::wstring wResult = L"";
	if (ListPrivs(hToken, &wResult))
	{
		if (wResult.size() > 0)
		{
			DWORD dwOutLen = (DWORD)wResult.length();
			DWORD dwResultLen = dwOutLen + 1;
			
			result = (LPWSTR)LocalAlloc(LPTR, dwResultLen * sizeof(WCHAR));
			if (result != NULL)
			{
				hr = StringCchCopyNW(result, dwResultLen, (LPWSTR)wResult.c_str(), dwOutLen);
			}
		}
	}

	if (hToken != NULL)
	{
		CloseHandle(hToken);
	}

	if (hProcess != NULL)
	{
		CloseHandle(hProcess);
	}

	if (SUCCEEDED(hr))
	{
		return result;
	}
	else
	{
		return NULL;
	}
}

#ifndef _DEBUG
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	UNREFERENCED_PARAMETER(hModule);
	UNREFERENCED_PARAMETER(lpReserved);

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
#else
int main()
{

	std::wstring input = L"";
	std::wstring out = L"";
	LPWSTR lpsz = ExecuteW((LPWSTR)input.c_str(), (DWORD)input.length());
	if (lpsz)
	{
		out = lpsz;
		LocalFree(lpsz);
		lpsz = NULL;

		if (out.size() > 0)
		{
			DWORD dwOutLen = (DWORD)out.length();
			DWORD dwResultLen = dwOutLen + 1;
			LPWSTR result = NULL;
			result = (LPWSTR)LocalAlloc(LPTR, dwResultLen*sizeof(WCHAR));
			if (result == NULL)
			{
				return -1;
			}
			HRESULT hr = StringCchCopyNW(result, dwResultLen, (LPWSTR)out.c_str(), dwOutLen);
			if (SUCCEEDED(hr))
			{
				wprintf(L"%s\n", result);
			}

			LocalFree(result);
		}
	}

	return 0;
}
#endif