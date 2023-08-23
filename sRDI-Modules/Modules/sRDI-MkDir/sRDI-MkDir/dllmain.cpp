#define no_init_all
#include <windows.h>
#include <strsafe.h>
#include <iostream>

DWORD threadID;

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::wstring GetLastErrorAsString()
{
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::wstring(); //No error message has been recorded
	}

	LPWSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::wstring message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

extern "C" __declspec(dllexport) LPWSTR ExecuteW(LPCWSTR lpUserdata, DWORD nUserdataLen)
{
	BOOL bRet = FALSE;
	if (!nUserdataLen)
	{
		return NULL;
	}

	

	DWORD parsedArgs = 0;
	DWORD length = 2;
	LPWSTR result = NULL;
	HRESULT hr = E_ABORT;

	LPWSTR *szArglist = NULL;
	szArglist = CommandLineToArgvW(lpUserdata, (int*)&parsedArgs);
	if (NULL != szArglist && parsedArgs == 1)
	{
		std::wstring path = szArglist[0];
		bRet = CreateDirectoryW(path.c_str(), NULL);
		std::wstring out = L"";
		if (bRet)
		{
			out = L"The operation completed successfully";
		}
		else
		{
			out = L"ERR: " + GetLastErrorAsString();
		}

		result = (LPWSTR)LocalAlloc(LPTR, (out.size() + 1) *sizeof(WCHAR));
		if (result != NULL)
		{
			hr = StringCchPrintfW(result, out.size() + 1, L"%s", out.c_str());
		}
	}

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
	std::wstring out = L"";
	std::wstring input = L"C:\\users\\user\\test";

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

