#pragma once
#define _CRT_SECURE_NO_WARNINGS 

#if _DEBUG
#define VERBOSE 1
#endif

#ifndef _DEBUG
#define VERBOSE 1
#endif


enum TaskCode {
	Task_Exit = 1,
	Task_Shell,
	Task_Cwd,
	Task_ChangeDir,
	Task_Whoami,
	Task_ShellInject,
	Task_pwd,
	Task_ps,
	Task_upload,
};

enum ReturnCode {
	Task_Success = 4,
	Task_Failure,
	Task_NotImplemented
};






#if VERBOSE
#define PRINTF(f_, ...) printf((f_), __VA_ARGS__)
#define CERR(x) std::cerr << x
#define COUT(x) std::cout << x  
#define WCOUT(x) std::wcout << x  
#else
#define PRINTF(X)
#define CERR(x)
#define COUT(x)   
#define WCOUT(x)  
#endif