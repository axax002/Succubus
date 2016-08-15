#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

#define FileMapName "Global\\fotile96"
#define ServerEventName "Global\\fotile96_0"
#define ClientEventName "Global\\fotile96_1"
#define SharedMemSize 0x100000
#define SharedMemBase 0x23300000
#define NumApis 50
#define NumStringLiterals 20
#define ApiBackupSize 1000
#define ParamsToRecord 16
#define ByteCodeSize 0x1000
#define DwordsToRestore 0xFF

#define hook_kernelbase

char* const gmem = (char*)0;
char* const mem = (char*)SharedMemBase;
FARPROC* const pFunc = (FARPROC*)mem;
DWORD* const last_ret_addr = (DWORD*)(pFunc + NumApis);
typedef char str_t[128];
str_t* const strBuf = (str_t*)(last_ret_addr + NumApis);
typedef char buf_t[ApiBackupSize];
buf_t* const hook_buf = (buf_t*)(strBuf + NumStringLiterals);
DWORD* const current_ebp = (DWORD*)(hook_buf + NumApis);
DWORD* const main_threadid = current_ebp + 1;
DWORD* const current_api = main_threadid + 1;
DWORD* const current_ret_addr = current_api + 1;
DWORD* const current_ret_value = current_ret_addr + 1;
DWORD* const current_params = current_ret_value + 1;
HANDLE* const hook_hInEvent = (HANDLE*)(current_params + ParamsToRecord);
HANDLE* const hook_hOutEvent = hook_hInEvent + 1;
DWORD* const if_int3 = (DWORD*)hook_hOutEvent + 1;
DWORD* const _eax = if_int3 + 1;
DWORD* const _ecx = _eax + 1;
DWORD* const _esi = _ecx + 1;
DWORD* const _edi = _esi + 1;
DWORD* const _stack_bak = _edi + 1;
FARPROC* const pHookProc = (FARPROC*)(_stack_bak + DwordsToRestore);


enum APIS {
	iOpenFileMapping,
	iMapViewOfFileEx,
	iExitProcess,
	iLoadLibraryA,
	iGetProcAddress,
	iVirtualProtect,
	imemcpy,
	iMessageBoxA,
	iVirtualAlloc,
	iGetVersionExA,
	iOpenEvent,
	iSetEvent,
	iWaitForSingleObject,
	iGetCurrentThreadId,
	iGetDriveTypeA,
	iCreateFileA,
	iMapViewOfFile,
	iTerminateProcess,
	ibaTerminateProcess,
	iVirtualFree,
	iGetVersion,
	iLoadLibraryExA,
	iGetLocalTime,
	iGetModuleHandleA,
	iOutputDebugStringA,
	iGetSystemDirectoryA,
	iSetFilePointer,
	iReadFile,
	iCloseHandle,
	iGetProcessHeap,
	iRtlAllocateHeap,
	iLAST
};

str_t api_name[NumApis];
int api_numof_params[NumApis];
int breakpoint;

enum STRING_LITERALS {
	sHelloWorld,
	sUSER32,
	sMSVCRT,
	smemcpy,
	sServerEvent,
	sClientEvent,
	sKERNELBASE
};

struct _THREAD_PARAM {
	FARPROC pFunc[3];
	char name[128];
};

#define shmapi(name) ((typeof(name)*)pFunc[i##name])
#define shmstr(name) ((char*)strBuf[s##name])
#define shmapi_raw(name) ((typeof(name)*)((DWORD)pFunc[i##name]+2))

#pragma GCC push_options
#pragma GCC optimize ("O1")
// Assume that at any instant during the execution, each stack frame belongs to different apis, i.e., inter-api calls are acyclic.
// UPD: this assumption does not hold sometimes, e.g., LoadLibraryExA
DWORD HookProc() {
	/* DWORD ebp, eax; */
	DWORD ebp;
	/* asm("int3;"); */
	// restoring DF is not implemented.
	asm("mov %%eax, %0;"::"m"(*_eax));
	asm("mov %%ecx, %0;"::"m"(*_ecx));
	asm("mov %%esi, %0;"::"m"(*_esi));
	asm("mov %%edi, %0;"::"m"(*_edi));
	asm("mov $0xFF, %ecx;mov %ebp, %esi");
	asm("mov %0, %%edi;std;rep movsl;cld;"::"i"(_stack_bak + DwordsToRestore - 1));
	asm("pushal;pushal;");
	asm("mov %0, %%eax;"::"m"(*_eax));
	asm("mov %0, %%ecx;"::"m"(*_ecx));
	asm("mov %0, %%esi;"::"m"(*_esi));
	asm("mov %0, %%edi;"::"m"(*_edi));
#define _ret { \
	asm("popal;popal;"); \
	asm("mov $0xFF, %ecx;mov %ebp, %edi;"); \
	asm("mov %0, %%esi;std;rep movsl;cld;"::"i"(_stack_bak + DwordsToRestore - 1)); \
	asm("mov %0, %%ecx;"::"m"(*_ecx)); \
	asm("mov %0, %%esi;"::"m"(*_esi)); \
	asm("mov %0, %%edi;"::"m"(*_edi)); \
	return *_eax; \
}
#define _ret2 { \
	asm("popal;popal;"); \
	return eax; \
}
	asm("mov %%ebp, %0;"::"m"(ebp));
	/* asm("mov %%eax, %0;"::"m"(eax)); */
	DWORD& ret_addr = *(DWORD*)(ebp+4);
	DWORD tid = shmapi(GetCurrentThreadId)();
	// mark the first thread calling in as the main thread
	if(!*main_threadid) *main_threadid = tid;
	if((*main_threadid != tid) || (*current_api && (*current_api != ret_addr || *current_ebp != *(DWORD*)ebp))) {
		ret_addr += 2;
		_ret;
		// let the call bypass if it is not from the main thread, or there is already an api frame
		// checking ret_addr only is not enough !! use stack frame as double-check 
	}
	if(*current_api) {
		*current_ret_value = *_eax;
		shmapi(SetEvent)(*hook_hOutEvent);
		shmapi(WaitForSingleObject)(*hook_hInEvent, INFINITE);
		*current_api = 0;
		ret_addr = *current_ret_addr;
		// debugger attaching => to be implemented.
		if(*if_int3) asm("int3;");
		_ret;
	}
	else {
		/* *current_ebp = ebp; */
		*current_api = ret_addr;
		*current_ebp = *(DWORD*)ebp;
		for(int i=0; i<ParamsToRecord; i++) current_params[i] = *(DWORD*)(ebp + 12 + 4*i);
		*current_ret_addr = *(DWORD*)(ebp+8);
		ret_addr += 2; // make this function return to the instruction after the short jump in the hooked api.
		*(DWORD*)(ebp+8) = *current_api;
		_ret;
	}
}

DWORD WINAPI ThreadProc(LPVOID lParam) {
	_THREAD_PARAM* pParam = (_THREAD_PARAM*)lParam;
#define paramapi(name) ((typeof(name)*)pParam->pFunc[i##name])
	HANDLE hMapFile = paramapi(OpenFileMapping)(FILE_MAP_ALL_ACCESS, FALSE, pParam->name);
	if(!hMapFile || paramapi(MapViewOfFileEx)(hMapFile, FILE_MAP_ALL_ACCESS|FILE_MAP_EXECUTE, 0, 0, 0, (LPVOID)SharedMemBase) == NULL) {
		// if fails, kill the target process
		paramapi(ExitProcess)(0);
	}
	// load memcpy()
	/* HMODULE hMod = shmapi(LoadLibraryA)(shmstr(MSVCRT)); */
	/* pFunc[imemcpy] = shmapi(GetProcAddress)(hMod, shmstr(memcpy)); */

	if((*hook_hInEvent = shmapi(OpenEvent)(EVENT_ALL_ACCESS, false, shmstr(ServerEvent))) == NULL || (*hook_hOutEvent = shmapi(OpenEvent)(EVENT_ALL_ACCESS, false, shmstr(ClientEvent))) == NULL) {
		// failed to open events, exit
		paramapi(ExitProcess)(0);
	}

// MinGW 开优化后行为奇怪。。（下面用了%256才work）
#define _hookapi(pfx, name) { \
	DWORD flag; \
	shmapi_raw(VirtualProtect)((LPVOID)((char*)pFunc[pfx##name] - 5), 13, PAGE_EXECUTE_READWRITE, &flag); \
	volatile DWORD code; \
	if(*(WORD*)pFunc[pfx##name] % 256 == 0xEB) { \
		char dst = *((char*)pFunc[pfx##name] + 1); \
		*((char*)pFunc[pfx##name] + 2) = 0xEB; \
		*((char*)pFunc[pfx##name] + 3) = dst - 2; \
	} \
	else if(*(WORD*)pFunc[pfx##name] == 0x25FF) { \
		DWORD dst = *(DWORD*)((DWORD)pFunc[pfx##name] + 2); \
		*((DWORD*)pFunc[pfx##name] + 1) = dst; \
		*((WORD*)pFunc[pfx##name] + 1) = 0x25FF; \
	} \
	*(char*)pFunc[pfx##name] = 0xEB; \
	*((char*)pFunc[pfx##name] + 1) = 0xF9; \
	*((char*)pFunc[pfx##name] - 5) = 0xE8; \
	*((DWORD*)pFunc[pfx##name] - 1) = (DWORD)pHookProc - (DWORD)pFunc[pfx##name]; \
	shmapi_raw(VirtualProtect)((LPVOID)((char*)pFunc[pfx##name] - 5), 13, flag, &flag); \
}
#define hookapi(name) _hookapi(i, name)
	hookapi(GetProcAddress);
	hookapi(VirtualAlloc);
	hookapi(GetVersionExA);
	hookapi(MessageBoxA);
	hookapi(GetDriveTypeA);
	hookapi(CreateFileA);
	hookapi(MapViewOfFile);
	hookapi(TerminateProcess);
	hookapi(VirtualFree);
	hookapi(LoadLibraryA);
	hookapi(GetVersion);
	hookapi(LoadLibraryExA);
	hookapi(GetLocalTime);
	hookapi(GetModuleHandleA);
	hookapi(OutputDebugStringA);
	hookapi(GetSystemDirectoryA);
	hookapi(SetFilePointer);
	/* hookapi(ReadFile); */
	hookapi(CloseHandle);
	hookapi(VirtualProtect);
	hookapi(GetProcessHeap);
	/* hookapi(RtlAllocateHeap); */

#ifdef hook_kernelbase
#define hookapi_ba(name) _hookapi(iba, name)
	if(shmapi_raw(LoadLibraryA)(shmstr(KERNELBASE)) != NULL) {
	hookapi_ba(TerminateProcess);
	}
#endif

	return 0;
}
#pragma GCC pop_options



void InjectCode(char* logname, char* appname, char* cmdline) {
	FILE* log;
	if((log = fopen(logname, "w")) == NULL) {
		printf("Master failed to open the log file.\n");
		return;
	}

	HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, SharedMemSize, FileMapName);
	if(hMapFile == NULL) {
		printf("Master failed to create file mapping.\n");
		return;
	}
	
	if(MapViewOfFileEx(hMapFile, FILE_MAP_ALL_ACCESS|FILE_MAP_EXECUTE, 0, 0, 0, (LPVOID)SharedMemBase) == NULL) {
		printf("Master failed to map the shared memory.\n");
		return;
	}

	HANDLE hInEvent, hOutEvent;
	if((hInEvent = CreateEvent(NULL, false, false, ClientEventName)) == NULL || (hOutEvent = CreateEvent(NULL, false, false, ServerEventName)) == NULL) {
		printf("Master failed to create events.\n");
		return;
	}


	_THREAD_PARAM param;
#define set_paramapi_addr(name) param.pFunc[i##name] = (FARPROC)name
	set_paramapi_addr(OpenFileMapping);
	set_paramapi_addr(MapViewOfFileEx);
	set_paramapi_addr(ExitProcess);
	strcpy(param.name, FileMapName);
#define init_api(name, num) { \
	pFunc[i##name] = (FARPROC)name; \
	strcpy(api_name[i##name], #name); \
	api_numof_params[i##name] = num; \
}
	init_api(OpenFileMapping, 3);
	init_api(MapViewOfFileEx, 6);
	init_api(ExitProcess, 1);
	init_api(LoadLibraryA, 1);
	init_api(GetProcAddress, 2);
	init_api(VirtualProtect, 4);
	init_api(MessageBoxA, 4);
	init_api(VirtualAlloc, 4);
	init_api(GetVersionExA, 1);
	init_api(OpenEvent, 3);
	init_api(SetEvent, 1);
	init_api(WaitForSingleObject, 2);
	init_api(GetCurrentThreadId, 0);
	init_api(GetDriveTypeA, 1);
	init_api(CreateFileA, 7);
	init_api(MapViewOfFile, 5);
	init_api(TerminateProcess, 2);
	init_api(VirtualFree, 3);
	init_api(GetVersion, 0);
	init_api(LoadLibraryExA, 3);
	init_api(GetLocalTime, 1);
	init_api(GetModuleHandleA, 1);
	init_api(OutputDebugStringA, 1);
	init_api(GetSystemDirectoryA, 2);
	init_api(SetFilePointer, 4);
	init_api(ReadFile, 5);
	init_api(CloseHandle, 1);
	init_api(GetProcessHeap, 0);

#ifdef hook_kernelbase
	HMODULE hModBA = LoadLibraryA("kernelbase.dll");
#define init_api_ba(name, num) { \
	pFunc[iba##name] = GetProcAddress(hModBA, #name); \
	strcpy(api_name[iba##name], #name "(KERNELBASE)"); \
	api_numof_params[iba##name] = num; \
}
	init_api_ba(TerminateProcess, 2);
#endif

#define init_api_dyn(name, dll, num) { \
	HMODULE hMod = GetModuleHandleA(dll); \
	pFunc[i##name] = GetProcAddress(hMod, #name); \
	strcpy(api_name[i##name], #name); \
	api_numof_params[i##name] = num; \
}
	init_api_dyn(RtlAllocateHeap, "ntdll.dll", 3);

#define set_shmstr(name, str) strcpy(strBuf[s##name], str)
	set_shmstr(HelloWorld, "HelloWorld!");
	set_shmstr(USER32, "user32.dll");
	set_shmstr(MSVCRT, "msvcrt.dll");
	set_shmstr(memcpy, "memcpy");
	set_shmstr(ServerEvent, ServerEventName);
	set_shmstr(ClientEvent, ClientEventName);
	set_shmstr(KERNELBASE, "kernelbase.dll");

	*current_api = 0;
	*main_threadid = 0;
	*if_int3 = 0;

	DWORD dwSize = (DWORD)ThreadProc - (DWORD)HookProc;
	memcpy((void*)pHookProc, (void*)HookProc, dwSize);

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	if(!CreateProcess(
			appname,
			cmdline,
			NULL,
			NULL,
			false,
			CREATE_SUSPENDED,
			NULL,
			NULL,
			&si,
			&pi
			)) {
		printf("Failed to create the target process.\n");
		return;
	}
	HANDLE hProcess = pi.hProcess;
	dwSize = sizeof(_THREAD_PARAM);
	LPVOID pRemoteBuf[2];
	pRemoteBuf[0] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteBuf[0], (LPVOID)&param, dwSize, NULL);

	dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;
	printf("dwSize(ThreadProc) = %x\n", dwSize);
	pRemoteBuf[1] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	printf("remote_addr(ThreadProc) = %x\n", (DWORD)pRemoteBuf[1]);
	WriteProcessMemory(hProcess, pRemoteBuf[1], (LPVOID)ThreadProc, dwSize, NULL);
	/* asm("int3;"); */
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf[1], pRemoteBuf[0], 0, NULL);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	ResumeThread(pi.hThread);

	int cnt = 0;

	while(1) {
		WaitForSingleObject(hInEvent, INFINITE);
		int i;
		for(i=0; i<iLAST; i++) if((DWORD)pFunc[i] == *current_api) break;
		char __buf[128];
		switch(i) {
			case(iGetProcAddress):
				ReadProcessMemory(hProcess, (LPCVOID)current_params[1], (LPVOID)__buf, 127, NULL);
				fprintf(log, "Main thread invokes %s, returns %x to %x with params: %x %x(%s)", api_name[i], *current_ret_value, *current_ret_addr, current_params[0], current_params[1], __buf);
				break;
			case(iCreateFileA):
			case(iGetDriveTypeA):
			case(iLoadLibraryA):
			case(iLoadLibraryExA):
			case(iGetModuleHandleA):
			case(iOutputDebugStringA):
				ReadProcessMemory(hProcess, (LPCVOID)current_params[0], (LPVOID)__buf, 127, NULL);
				fprintf(log, "Main thread invokes %s, returns %x to %x with params: %x(%s)", api_name[i], *current_ret_value, *current_ret_addr, current_params[0], __buf);
				for(int j=1; j<api_numof_params[i]; j++) fprintf(log, " %x", current_params[j]);
				break;
			default:
				fprintf(log, "Main thread invokes %s, returns %x to %x with params:", api_name[i], *current_ret_value, *current_ret_addr);
				for(int j=0; j<api_numof_params[i]; j++) fprintf(log, " %x", current_params[j]);
				break;
		}
		fprintf(log, ", ebp=%x", *current_ebp);
		fputc('\n', log);
		fflush(log);

		// deprecated
		cnt++;
		if(cnt == breakpoint) {
			puts("Target process is waiting a debugger to attach.");
			getchar();
			puts("Target process continues to run.");
		}
		SetEvent(hOutEvent);
	}

	/* CloseHandle(hProcess); */
}

int main(int argc, char** argv) {
	puts("");
	if(argc < 3) {
		printf("USAGE: %s log-filename target [command-line] [breakpoints]\n", argv[0]);
		return 1;
	}
	if(argc >= 5) breakpoint = atol(argv[4]);
		else breakpoint = 0;
	if(argc == 6) InjectCode(argv[1], argv[2], NULL);
		else InjectCode(argv[1], argv[2], argc == 3 ? NULL : argv[3]);
	return 0;
}
