#define no_init_all
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <iostream>
#include <vector>

#include <stdlib.h>

#include <shellapi.h>
// ref: https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
#pragma comment (lib, "Shell32.lib") // CommandLineToArgvW

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

BOOL SetPrivs(HANDLE& hProcess, LPCWSTR priv, BOOL enabled = TRUE)
{
	HANDLE hToken = NULL;
	BOOL bRet = FALSE;

	// use Function OpenProcessToken
	// Extract the hToken from hProcess and TOKEN_ADJUST_PRIVILEGES.
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

// https://github.com/vxunderground/VX-API/blob/main/VX-API/StringCompare.cpp
INT StringCompareW(LPCWSTR String1, LPCWSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCWSTR)String1 < *(LPCWSTR)String2) ? -1 : +1);
}

extern "C" __declspec(dllexport) LPWSTR ExecuteW(LPCWSTR lpUserdata, DWORD nUserdataLen)
{
	if (!nUserdataLen)
	{
		return NULL;
	}


	HRESULT hr = E_ABORT;
	DWORD parsedArgs = 0;
	DWORD length = 2;
	LPWSTR result = NULL;
	LPWSTR *szArglist = NULL;
	
	szArglist = CommandLineToArgvW(lpUserdata, (int*)&parsedArgs);
	LPWSTR priv = NULL;
	BOOL state = FALSE;
	
	if (NULL != szArglist && parsedArgs == 2)
	{
		priv = szArglist[0];
		if (StringCompareW(szArglist[1], L"enabled") == 0)
		{
			state = TRUE;
		}
		
		HANDLE hProcess = GetCurrentProcess();
		BOOL bRet = SetPrivs(hProcess, priv, state);
		if (bRet)
		{
			result = (LPWSTR)LocalAlloc(LPTR, length*sizeof(WCHAR));
			if (result != NULL)
			{
#if _DEBUG
				MessageBoxW(NULL, L"returned TRUE!", szArglist[0], MB_OK);
#endif
				hr = StringCchPrintfW(result, length, L"%s", L"1");
			}
		}

		if (hProcess)
		{
			CloseHandle(hProcess);
		}
	}
	
	// Free memory allocated for CommandLineToArgvW arguments.
	if (szArglist)
	{
		SecureZeroMemory(szArglist, sizeof(szArglist));
		LocalFree(szArglist);
		szArglist = NULL;
	}

	
	if (SUCCEEDED(hr))
	{
		return result;
	}
	else
	{
#if _DEBUG
		MessageBoxW(NULL, L"StringCchPrintfW failed", L"OUTPUT", MB_OK);
#endif
		return NULL;
	}
}

#ifndef _DEBUG
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
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
	std::wstring input = L"SeChangeNotifyPrivilege disabled";
	std::wstring out = L"";
	LPWSTR lpsz = ExecuteW(input.c_str(), (DWORD)input.length());
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
			result = (LPWSTR)LocalAlloc(LPTR, dwResultLen *sizeof(WCHAR));
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