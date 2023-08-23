//
// https://gist.github.com/SuperKogito/00e0ad0d5b2b567d74a10fe18c048776
// with small modifications.
//
/*******************************************************************************************
 * \file   CaptureSceenshotUsingGdiplus.cpp
 * \brief  capture screenshot using GDI+ and save it to drive or memory.
 *
 * \author SuperKogito
 * \date   July 2020
 *
 * @note:
 * references and sources:
 * - https://docs.microsoft.com/en-us/windows/win32/gdiplus/-gdiplus-gdi-start
 * - https://docs.microsoft.com/en-us/windows/win32/gdiplus/-gdiplus-about-gdi--about
 * - https://stackoverflow.com/questions/5345803/does-gdi-have-standard-image-encoder-clsids
 * - https://stackoverflow.com/questions/1584202/gdi-bitmap-save-problem
 ********************************************************************************************/
#pragma once
#include <windows.h>
#pragma warning( disable : 4458 )
#include <gdiplus.h>
#include <vector>
#include <tchar.h>
#include <stdio.h>
#include <fstream>
#include <iostream>
#include "atlimage.h"
#include <strsafe.h>
#include <map>
using namespace Gdiplus;
using namespace std;

#pragma comment(lib,"gdiplus.lib")


/**
 * Create a Bitmap file header..
 *
 * @param hwindowDC : window handle.
 * @param widht	    : image width.
 * @param height    : image height.
 *
 * @return Bitmap header.
 */
BITMAPINFOHEADER createBitmapHeader(int width, int height)
{
	BITMAPINFOHEADER  bi;

	// create a bitmap
	bi.biSize = sizeof(BITMAPINFOHEADER);
	bi.biWidth = width;
	bi.biHeight = -height;  //this is the line that makes it draw upside down or not
	bi.biPlanes = 1;
	bi.biBitCount = 32;
	bi.biCompression = BI_RGB;
	bi.biSizeImage = 0;
	bi.biXPelsPerMeter = 0;
	bi.biYPelsPerMeter = 0;
	bi.biClrUsed = 0;
	bi.biClrImportant = 0;

	return bi;
}

/**
 * Capture a screen and return the handle to its bitmap.
 *
 * @param hwnd : window handle.
 */
HBITMAP GdiPlusScreenCapture(HWND hWnd)
{
	// get handles to a device context (DC)
	HDC hwindowDC = GetDC(hWnd);
	HDC hwindowCompatibleDC = CreateCompatibleDC(hwindowDC);
	SetStretchBltMode(hwindowCompatibleDC, COLORONCOLOR);

	// define scale, height and width
	//int scale = 1;
	int screenx = GetSystemMetrics(SM_XVIRTUALSCREEN);
	int screeny = GetSystemMetrics(SM_YVIRTUALSCREEN);
	int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
	int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

	// create a bitmap
	HBITMAP hbwindow = CreateCompatibleBitmap(hwindowDC, width, height);
	BITMAPINFOHEADER bi = createBitmapHeader(width, height);

	// use the previously created device context with the bitmap
	SelectObject(hwindowCompatibleDC, hbwindow);

	// Starting with 32-bit Windows, GlobalAlloc and LocalAlloc are implemented as wrapper functions that call HeapAlloc using a handle to the process's default heap. 
	// Therefore, GlobalAlloc and LocalAlloc have greater overhead than HeapAlloc.
	DWORD dwBmpSize = ((width * bi.biBitCount + 31) / 32) * 4 * height;
	HANDLE hDIB = GlobalAlloc(GHND, dwBmpSize);
	char* lpbitmap = (char*)GlobalLock(hDIB);

	// copy from the window device context to the bitmap device context
	StretchBlt(hwindowCompatibleDC, 0, 0, width, height, hwindowDC, screenx, screeny, width, height, SRCCOPY);   //change SRCCOPY to NOTSRCCOPY for wacky colors !
	GetDIBits(hwindowCompatibleDC, hbwindow, 0, height, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

	// avoid memory leak
	DeleteDC(hwindowCompatibleDC);
	ReleaseDC(hWnd, hwindowDC);

	return hbwindow;
}


/**
 * Save a bitmap to memory using its handle.
 *
 * @param hbitmap    : pointer to a bitmap handle.
 * @param data       : pointer to a vector of bytes.
 * @param dataformat : format of datatype to save data according to it.
 *
 * @return boolean representing whether the saving successful was or not.
 */
bool saveToMemory(HBITMAP* hbitmap, std::vector<BYTE>& data, std::string dataFormat = "png")
{
	Gdiplus::Bitmap bmp(*hbitmap, nullptr);
	// write to IStream
	IStream* istream = nullptr;
	CreateStreamOnHGlobal(NULL, TRUE, &istream);

	// define encoding
	CLSID clsid;
	if (dataFormat.compare("bmp") == 0) { CLSIDFromString(L"{557cf400-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
	else if (dataFormat.compare("jpg") == 0) { CLSIDFromString(L"{557cf401-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
	else if (dataFormat.compare("gif") == 0) { CLSIDFromString(L"{557cf402-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
	else if (dataFormat.compare("tif") == 0) { CLSIDFromString(L"{557cf405-1a04-11d3-9a73-0000f81ef32e}", &clsid); }
	else if (dataFormat.compare("png") == 0) { CLSIDFromString(L"{557cf406-1a04-11d3-9a73-0000f81ef32e}", &clsid); }

	Gdiplus::Status status = bmp.Save(istream, &clsid, NULL);
	if (status != Gdiplus::Status::Ok)
		return false;

	// get memory handle associated with istream
	HGLOBAL hg = NULL;
	GetHGlobalFromStream(istream, &hg);

	// copy IStream to buffer
	int bufsize = (int)GlobalSize(hg);
	data.resize(bufsize);

	// lock & unlock memory
	LPVOID pimage = GlobalLock(hg);
	memcpy(&data[0], pimage, bufsize);
	GlobalUnlock(hg);
	istream->Release();
	return true;
}

extern "C" __declspec(dllexport) LPBYTE ExecuteW(LPCWSTR lpUserdata, DWORD* nUserdataLen)
{
	UNREFERENCED_PARAMETER(lpUserdata);
	UNREFERENCED_PARAMETER(nUserdataLen);

	GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	// get the bitmap handle to the bitmap screenshot
	HWND hWnd = GetDesktopWindow();
	HBITMAP hBmp = GdiPlusScreenCapture(hWnd);

	// save as png to memory 

	std::string enc;
	LPBYTE pDataCopy = NULL;
	std::vector<BYTE> data;
	std::string dataFormat = "png";
	if (saveToMemory(&hBmp, data, dataFormat))
	{

		DWORD pDataLen = static_cast<DWORD>(data.size());
		*nUserdataLen = pDataLen;

		if (pDataLen > 0) {
			pDataCopy = reinterpret_cast<LPBYTE>(malloc(pDataLen + 1)); // +1 for null termination
			if (pDataCopy) {
				memcpy(pDataCopy, data.data(), pDataLen);

			}
		}

	}

	return pDataCopy;
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
	// Initialize GDI+.
	/*GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	// get the bitmap handle to the bitmap screenshot
	HWND hWnd = GetDesktopWindow();
	HBITMAP hBmp = GdiPlusScreenCapture(hWnd);

	// save as png to memory
	std::vector<BYTE> data;
	std::string dataFormat = "bmp";

	if (saveToMemory(&hBmp, data, dataFormat))
	{
		std::wcout << "Screenshot saved to memory" << std::endl;

		// save from memory to file
		//std::ofstream fout("Screenshot-m1." + dataFormat, std::ios::binary);
		//fout.write((char*)data.data(), data.size());
	}
	else
		std::wcout << "Error: Couldn't save screenshot to memory" << std::endl;


	// save as png (method 2)
	CImage image;
	image.Attach(hBmp);
	image.Save("Screenshot-m2.png");

	GdiplusShutdown(gdiplusToken);*/
	std::wstring input = L"";
	std::wstring out = L"";

	DWORD length = 0;
	LPBYTE lpsz = ExecuteW((LPWSTR)input.c_str(), &length);
	//wprintf(wResult.c_str());
	if (lpsz)
	{
		std::string dataFormat = "png";
		std::cout << length;
		std::vector<BYTE> dataVector;
		dataVector.assign(lpsz, lpsz + length);
		std::ofstream fout("Screenshot." + dataFormat, std::ios::binary);
		fout.write((char*)dataVector.data(), dataVector.size());
	}
	return 0;
}
#endif