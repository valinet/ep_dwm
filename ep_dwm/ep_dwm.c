#include "ep_dwm.h"

LPWSTR                ep_dwm_g_wszServiceName;
LPWSTR                ep_dwm_g_wszEventName;
SERVICE_STATUS        ep_dwm_g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE ep_dwm_g_StatusHandle = NULL;
HANDLE                ep_dwm_g_Service = INVALID_HANDLE_VALUE;
HANDLE                ep_dwm_g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HANDLE                ep_dwm_g_ServiceSessionChangeEvent = INVALID_HANDLE_VALUE;
#define				  EP_DWM_NUM_EVENTS 2
#define               EP_DWM_SETUP_TIME 2000
#define               EP_DWM_GRACE_TIME 5000
#define				  EP_DWM_GROW 10
#define               EP_DWM_MAX_NUM_MODULES 200
#define               EP_DWM_REASON_NONE 0
#define               EP_DWM_REASON_TERMINATION_BYUSER 1
#define               EP_DWM_REASON_EARLIER_ERROR 2

#define STRINGER_INTERNAL(x) #x
#define STRINGER(x) STRINGER_INTERNAL(x)

#define CLEAR(x) { \
	DPA_DestroyCallback(dpaHandlesList, ep_dwm_DestroyHandle, dpaExclusionList); \
	if (x == EP_DWM_REASON_TERMINATION_BYUSER) OutputDebugStringW(L"ep_dwm: Terminating as per user request (line " _T(STRINGER(__LINE__)) L").\n"); \
	else if (x == EP_DWM_REASON_EARLIER_ERROR) OutputDebugStringW(L"ep_dwm: Terminating due to earlier failure (line " _T(STRINGER(__LINE__)) L")!\n"); \
}

#define CLEAR_AND_DEPATCH(x) { \
	for (unsigned int i = EP_DWM_NUM_EVENTS; i < DPA_GetPtrCount(dpaHandlesList); ++i) \
	{ \
		ep_dwm_PatchProcess(wszUDWMPath, DPA_FastGetPtr(dpaHandlesList, i), dpaPatchSites, /*bRestore*/ TRUE); \
	} \
	CLEAR(x); \
}

#define REPORT_ON_PROCESS(s, i) { \
	DWORD dwExitCode = 0; \
	GetExitCodeProcess(DPA_FastGetPtr(dpaHandlesList, i), &dwExitCode); \
	if (dwExitCode && dwExitCode != 0xd00002fe) \
	{ \
		if (s) { \
			dwFailedNum = i; \
			dwRes = dwExitCode; \
		} \
		OutputDebugStringW(L"ep_dwm: One of the processes has crashed (line " _T(STRINGER(__LINE__)) L")!\n"); \
	} \
	else \
	{ \
		if (!dwRes || !s) \
		{ \
			if (s) { \
				dwFailedNum = i; \
				dwRes = 0; \
			} \
			if (dwExitCode == 0xd00002fe) \
			{ \
				OutputDebugStringW(L"ep_dwm: The Desktop Window Manager has exited with code (0xd00002fe) (line " _T(STRINGER(__LINE__)) L")!\n"); \
			} \
			else \
			{ \
				OutputDebugStringW(L"ep_dwm: An instance of the Desktop Window Manager has closed (line " _T(STRINGER(__LINE__)) L")!\n"); \
			} \
		} \
	} \
}

typedef struct PatchSite
{
	UINT_PTR offset;
	BYTE newCode[8];
	BYTE oldCode[8];
	DWORD codeLength;
} PatchSite;

static int ep_dwm_DestroyPatchSite(void* p, void* pUnused)
{
	PatchSite* ps = p;
	free(ps);
	return 1;
}

static int ep_dwm_DestroyHandle(HANDLE h, HDPA dpaExclusionList)
{
	BOOL bShouldClose = TRUE;
	for (unsigned int i = 0; i < DPA_GetPtrCount(dpaExclusionList); ++i)
	{
		if (DPA_FastGetPtr(dpaExclusionList, i) == h)
		{
			bShouldClose = FALSE;
		}
	}
	if (bShouldClose)
	{
		CloseHandle(h);
	}
	return 1;
}

static BOOL MaskCompare(PVOID pBuffer, LPCSTR lpPattern, LPCSTR lpMask)
{
	for (PBYTE value = (PBYTE)pBuffer; *lpMask; ++lpPattern, ++lpMask, ++value)
	{
		if (*lpMask == 'x' && *(LPCBYTE)lpPattern != *value)
			return FALSE;
	}

	return TRUE;
}

static __declspec(noinline) PVOID FindPatternHelper(PVOID pBase, SIZE_T dwSize, LPCSTR lpPattern, LPCSTR lpMask)
{
	for (SIZE_T index = 0; index < dwSize; ++index)
	{
		PBYTE pAddress = (PBYTE)pBase + index;

		if (MaskCompare(pAddress, lpPattern, lpMask))
			return pAddress;
	}

	return NULL;
}

PVOID FindPattern(PVOID pBase, SIZE_T dwSize, LPCSTR lpPattern, LPCSTR lpMask)
{
	dwSize -= strlen(lpMask);
	return FindPatternHelper(pBase, dwSize, lpPattern, lpMask);
}

#if defined(_M_ARM64)
__forceinline DWORD ARM64_ReadBits(DWORD value, int h, int l)
{
	return (value >> l) & ((1 << (h - l + 1)) - 1);
}

__forceinline int ARM64_SignExtend(DWORD value, int numBits)
{
	DWORD mask = 1 << (numBits - 1);
	if (value & mask)
		value |= ~((1 << numBits) - 1);
	return (int)value;
}

__forceinline int ARM64_ReadBitsSignExtend(DWORD insn, int h, int l)
{
	return ARM64_SignExtend(ARM64_ReadBits(insn, h, l), h - l + 1);
}

__forceinline BOOL ARM64_IsInRange(int value, int bitCount)
{
	int minVal = -(1 << (bitCount - 1));
	int maxVal = (1 << (bitCount - 1)) - 1;
	return value >= minVal && value <= maxVal;
}

__forceinline BOOL ARM64_IsBL(DWORD insn) { return ARM64_ReadBits(insn, 31, 26) == 0b100101; }

__forceinline DWORD* ARM64_FollowBL(DWORD* pInsnBL)
{
	DWORD insnBL = *pInsnBL;
	if (!ARM64_IsBL(insnBL))
		return NULL;
	int imm26 = ARM64_ReadBitsSignExtend(insnBL, 25, 0);
	return pInsnBL + imm26; // offset = imm26 * 4
}

__forceinline DWORD ARM64_MakeB(int imm26)
{
	if (!ARM64_IsInRange(imm26, 26))
		return 0;
	return 0b000101 << 26 | imm26 & (1 << 26) - 1;
}
#endif

static DWORD ep_dwm_DeterminePatchAddresses(const WCHAR* pwszUDWMPath, HDPA dpaPatchSites)
{
	DWORD dwRes = 0;

	HMODULE hModule = LoadLibraryW(pwszUDWMPath);
	if (!hModule)
	{
		OutputDebugStringW(L"ep_dwm: Failed (LoadLibraryW) (line " _T(STRINGER(__LINE__)) L")!\n");
		return __LINE__;
	}

	PBYTE beginText = NULL;
	DWORD sizeText = 0;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((u_char*)dosHeader + dosHeader->e_lfanew);
		if (ntHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			PIMAGE_SECTION_HEADER firstSection = IMAGE_FIRST_SECTION(ntHeader);
			for (unsigned int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
			{
				PIMAGE_SECTION_HEADER section = firstSection + i;
				if (!strncmp(section->Name, ".text", 5))
				{
					beginText = (PBYTE)dosHeader + section->VirtualAddress;
					sizeText = section->SizeOfRawData;
					break;
				}
			}
		}
	}
	if (!beginText || !sizeText)
	{
		return __LINE__;
	}

#if defined(_M_X64)
	// CORNER_STYLE CTopLevelWindow::GetEffectiveCornerStyle()
	// 48 83 EC 38 0F 29 74 24 20 0F 57 F6 E8 ?? ?? ?? ?? 83 E8 02
	//                                        ^^^^^^^^^^^
	// -> 48 C7 C0 01 00 00 00 C3
	// Ref: float CTopLevelWindow::GetRadiusFromCornerStyle()
	PBYTE match = FindPattern(
		beginText, sizeText,
		"\x48\x83\xEC\x38\x0F\x29\x74\x24\x20\x0F\x57\xF6\xE8\x00\x00\x00\x00\x83\xE8\x02",
		"xxxxxxxxxxxxx????xxx"
	);
	if (match)
	{
		match += 12; // Point to E8
		match += 5 + *(int*)(match + 1);
	}
	if (match)
	{
		PatchSite* site = calloc(1, sizeof(PatchSite));
		if (site)
		{
			site->offset = match - (PBYTE)hModule;
			site->codeLength = 8;
			memcpy(site->newCode, "\x48\xC7\xC0\x01\x00\x00\x00\xC3", site->codeLength);
			memcpy(site->oldCode, match, site->codeLength);
			DPA_AppendPtr(dpaPatchSites, site);
		}
	}
#elif defined(_M_ARM64)
	// CORNER_STYLE CTopLevelWindow::GetEffectiveCornerStyle()
	// E8 0F 1F FC FD 7B ?? A9 FD 03 00 91 08 E4 00 2F ?? ?? ?? ?? 1F ?? 00 71
	//                                                 ^^^^^^^^^^^
	// -> 20 00 80 D2 C0 03 5F D6
	// Ref: float CTopLevelWindow::GetRadiusFromCornerStyle()
	PBYTE match = FindPattern(
		beginText, sizeText,
		"\xE8\x0F\x1F\xFC\xFD\x7B\x00\xA9\xFD\x03\x00\x91\x08\xE4\x00\x2F\x00\x00\x00\x00\x1F\x00\x00\x71",
		"xxxxxx?xxxxxxxxx????x?xx"
	);
	if (match)
	{
		match += 16;
		match = (PBYTE)ARM64_FollowBL((DWORD*)match);
	}
	if (match)
	{
		PatchSite* site = calloc(1, sizeof(PatchSite));
		if (site)
		{
			site->offset = match - (PBYTE)hModule;
			site->codeLength = 8;
			memcpy(site->newCode, "\x20\x00\x80\xD2\xC0\x03\x5F\xD6", site->codeLength);
			memcpy(site->oldCode, match, site->codeLength);
			DPA_AppendPtr(dpaPatchSites, site);
		}
	}

	// Inlined occurrences of the above function (can also be in the function itself)
	// 28 6D 40 39 68 00 00 34 28 75 40 39 ?? ?? 00 34 28 21 40 B9 1F 09 00 71 ?? ?? 00 54
	//                                                                         ^^^^^^^^^^^ B.GE to B
	// Max 3 occurrences
	PBYTE cur = beginText;
	for (int i = 0; i < 3; ++i)
	{
		match = FindPattern(
			cur, sizeText - (cur - beginText),
			"\x28\x6D\x40\x39\x68\x00\x00\x34\x28\x75\x40\x39\x00\x00\x00\x34\x28\x21\x40\xB9\x1F\x09\x00\x71\x00\x00\x00\x54",
			"xxxxxxxxxxxx??xxxxxxxxxx??xx"
		);
		if (!match)
			break; // No more matches

		cur = match + 28;
		match += 24; // Point to B.GE
		DWORD insnBCond = *(DWORD*)match;
		int cond = ARM64_ReadBits(insnBCond, 3, 0);
		if (cond != 0b1010) // GE
		{
			--i; // Not this one
			continue;
		}

		int imm19 = ARM64_ReadBitsSignExtend(insnBCond, 23, 5);
		DWORD newInsn = ARM64_MakeB(imm19);
		if (!newInsn)
			continue;

		PatchSite* site = calloc(1, sizeof(PatchSite));
		if (site)
		{
			site->offset = match - (PBYTE)hModule;
			site->codeLength = 4;
			memcpy(site->newCode, &newInsn, site->codeLength);
			memcpy(site->oldCode, match, site->codeLength);
			DPA_AppendPtr(dpaPatchSites, site);
		}
	}
#endif

	FreeLibrary(hModule);

	if (DPA_GetPtrCount(dpaPatchSites) == 0)
	{
		OutputDebugStringW(L"ep_dwm: Unable to identify patch area!\n");
		dwRes = __LINE__;
	}

	return dwRes;
}

static DWORD ep_dwm_PatchProcess(const WCHAR* pwszUDWMPath, HANDLE hProcess, HDPA dpaPatchSites, BOOL bRestore)
{
	DWORD dwRes = 0;

	MODULEENTRY32 me32;
	ZeroMemory(&me32, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
	if (!hSnapshot)
	{
		OutputDebugStringW(L"ep_dwm: Failed (CreateToolhelp32Snapshot TH32CS_SNAPMODULE) (line " _T(STRINGER(__LINE__)) L")!\n");
		return __LINE__;
	}
	if (Module32FirstW(hSnapshot, &me32) == TRUE)
	{
		do
		{
			if (!_wcsicmp(me32.szExePath, pwszUDWMPath))
			{
				for (unsigned int j = 0; dwRes == 0 && j < DPA_GetPtrCount(dpaPatchSites); ++j)
				{
					PatchSite* ps = DPA_FastGetPtr(dpaPatchSites, j);

					UINT_PTR pfn = me32.modBaseAddr + ps->offset;
					DWORD dwOldProtect = 0;
					SIZE_T dwNumberOfBytesWritten = 0;
					if (!VirtualProtectEx(hProcess, (LPVOID)pfn, ps->codeLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
					{
						OutputDebugStringW(L"ep_dwm: Failed (VirtualProtectEx) (line " _T(STRINGER(__LINE__)) L")!\n");
						dwRes = __LINE__;
						break;
					}

					WriteProcessMemory(hProcess, (LPVOID)pfn, bRestore ? ps->oldCode : ps->newCode, ps->codeLength, &dwNumberOfBytesWritten);
					if (!dwNumberOfBytesWritten || dwNumberOfBytesWritten != ps->codeLength)
					{
						OutputDebugStringW(L"ep_dwm: Failed (WriteProcessMemory) (line " _T(STRINGER(__LINE__)) L")!\n");
						dwRes = __LINE__;
					}

					VirtualProtectEx(hProcess, (LPVOID)pfn, ps->codeLength, dwOldProtect, &dwOldProtect);
				}
				break;
			}
		} while (dwRes == 0 && Module32NextW(hSnapshot, &me32) == TRUE);
	}
	CloseHandle(hSnapshot);

	return dwRes;
}

static DWORD WINAPI ep_dwm_ServiceThread(LPVOID lpUnused)
{
	WCHAR wszDWMPath[MAX_PATH];
	GetSystemDirectoryW(wszDWMPath, MAX_PATH);
	wcscat_s(wszDWMPath, MAX_PATH, L"\\dwm.exe");

	WCHAR wszUDWMPath[MAX_PATH];
	GetSystemDirectoryW(wszUDWMPath, MAX_PATH);
	wcscat_s(wszUDWMPath, MAX_PATH, L"\\uDWM.dll");

	HDPA dpaPatchSites = DPA_Create(EP_DWM_GROW);
	if (!dpaPatchSites)
	{
		OutputDebugStringW(L"ep_dwm: Failed (DPA_Create) (line " _T(STRINGER(__LINE__)) L")!\n");
		return __LINE__;
	}

	DWORD dwRes = ep_dwm_DeterminePatchAddresses(wszUDWMPath, dpaPatchSites);
	if (dwRes != 0)
	{
		return dwRes;
	}

	HDPA dpaExclusionList = DPA_Create(EP_DWM_NUM_EVENTS);
	if (!dpaExclusionList)
	{
		dwRes = __LINE__;
		OutputDebugStringW(L"ep_dwm: Failed (DPA_Create) (line " _T(STRINGER(__LINE__)) L")!\n");
		return dwRes;
	}
	DPA_AppendPtr(dpaExclusionList, ep_dwm_g_ServiceStopEvent);
	DPA_AppendPtr(dpaExclusionList, ep_dwm_g_ServiceSessionChangeEvent);

	while (TRUE)
	{
		DWORD dwFailedNum = 0;

		HDPA dpaHandlesList = DPA_Create(EP_DWM_GROW);
		if (!dpaHandlesList)
		{
			dwRes = __LINE__;
			OutputDebugStringW(L"ep_dwm: Failed (DPA_Create) (line " _T(STRINGER(__LINE__)) L")!\n");
			break;
		}

		for (unsigned int i = 0; i < DPA_GetPtrCount(dpaExclusionList); ++i)
		{
			DPA_AppendPtr(dpaHandlesList, DPA_FastGetPtr(dpaExclusionList, i));
		}

		// Make list of dwm.exe processes
		PROCESSENTRY32 pe32;
		ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
		pe32.dwSize = sizeof(PROCESSENTRY32);
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!hSnapshot)
		{
			DPA_Destroy(dpaHandlesList);
			OutputDebugStringW(L"ep_dwm: Failed (CreateToolhelp32Snapshot TH32CS_SNAPPROCESS) (line " _T(STRINGER(__LINE__)) L")!\n");
			dwRes = __LINE__;
			break;
		}
		if (Process32FirstW(hSnapshot, &pe32) == TRUE)
		{
			do
			{
				if (!_wcsicmp(pe32.szExeFile, L"dwm.exe"))
				{
					HANDLE hProcess = OpenProcess(
						PROCESS_QUERY_LIMITED_INFORMATION |
						PROCESS_VM_OPERATION |
						PROCESS_VM_READ |
						PROCESS_VM_WRITE |
						//PROCESS_CREATE_THREAD |
						SYNCHRONIZE,
						FALSE,
						pe32.th32ProcessID
					);
					if (!hProcess)
					{
						OutputDebugStringW(L"ep_dwm: Failed (OpenProcess) (line " _T(STRINGER(__LINE__)) L")!\n");
						continue;
					}
					TCHAR wszProcessPath[MAX_PATH];
					DWORD dwLength = MAX_PATH;
					QueryFullProcessImageNameW(hProcess, 0, wszProcessPath, &dwLength);
					if (!_wcsicmp(wszProcessPath, wszDWMPath))
					{
						DPA_AppendPtr(dpaHandlesList, hProcess);
					}
					else
					{
						CloseHandle(hProcess);
					}
				}
			} while (Process32NextW(hSnapshot, &pe32) == TRUE);
		}
		CloseHandle(hSnapshot);

		// If process list is empty, retry
		if (DPA_GetPtrCount(dpaHandlesList) <= DPA_GetPtrCount(dpaExclusionList))
		{
			DPA_Destroy(dpaHandlesList);
			OutputDebugStringW(L"ep_dwm: Desktop Window Manager is not running!\n");
			OutputDebugStringW(L"ep_dwm: Retry (line " _T(STRINGER(__LINE__)) L").\n");
			continue;
		}

		// Give processes a bit of time to start up
		OutputDebugStringW(L"ep_dwm: Waiting " _T(STRINGER(EP_DWM_SETUP_TIME)) L" ms for the processes to be ready.\n");
		if (WaitForSingleObject(ep_dwm_g_ServiceStopEvent, EP_DWM_SETUP_TIME) == WAIT_OBJECT_0)
		{
			CLEAR(EP_DWM_REASON_TERMINATION_BYUSER);
			break;
		}

		// Attempt to patch each process
		for (unsigned int i = EP_DWM_NUM_EVENTS; i < DPA_GetPtrCount(dpaHandlesList); ++i)
		{
			if (ep_dwm_PatchProcess(wszUDWMPath, DPA_FastGetPtr(dpaHandlesList, i), dpaPatchSites, /*bRestore*/ FALSE))
			{
				dwFailedNum = i;
				dwRes = __LINE__;
				break;
			}
		}
		if (dwFailedNum)
		{
			// If patching for a process failed, reverse the patch on the previous ones and give up
			CLEAR_AND_DEPATCH(EP_DWM_REASON_EARLIER_ERROR);
			break;
		}
		OutputDebugStringW(L"ep_dwm: Patched processes.\n");

		// Give patch a bit of time in order to observe if it lead to program crash
		OutputDebugStringW(L"ep_dwm: Waiting " _T(STRINGER(EP_DWM_GRACE_TIME)) L" ms to determine if patch doesn't lead to crash.\n");
		if (WaitForSingleObject(ep_dwm_g_ServiceStopEvent, EP_DWM_GRACE_TIME) == WAIT_OBJECT_0)
		{
			CLEAR_AND_DEPATCH(EP_DWM_REASON_TERMINATION_BYUSER);
			break;
		}

		// Check if any of the processes has terminated, then it's likely the patch crashed it
		for (unsigned int i = EP_DWM_NUM_EVENTS; i < DPA_GetPtrCount(dpaHandlesList); ++i)
		{
			if (WaitForSingleObject(DPA_FastGetPtr(dpaHandlesList, i), 0) == WAIT_OBJECT_0)
			{
				REPORT_ON_PROCESS(TRUE, i);
			}
		}
		if (dwFailedNum)
		{
			// If one of the processes just closed, wait a bit and repatch
			if (!dwRes)
			{
				if (WaitForSingleObject(ep_dwm_g_ServiceStopEvent, EP_DWM_SETUP_TIME) == WAIT_OBJECT_0)
				{
					CLEAR_AND_DEPATCH(EP_DWM_REASON_TERMINATION_BYUSER);
					break;
				}
				CLEAR(EP_DWM_REASON_NONE);
				OutputDebugStringW(L"ep_dwm: Retry (line " _T(STRINGER(__LINE__)) L").\n");
				continue;
			}
			// If at least one process crashed, unpatch the rest and give up
			CLEAR_AND_DEPATCH(EP_DWM_REASON_EARLIER_ERROR);
			break;
		}

		// Wait for an external signal or for any of the processes to terminate
		OutputDebugStringW(L"ep_dwm: Waiting for a signal or process termination.\n");
		DWORD dwRv = WaitForMultipleObjects(DPA_GetPtrCount(dpaHandlesList), DPA_GetPtrPtr(dpaHandlesList), FALSE, INFINITE);
		OutputDebugStringW(L"ep_dwm: Wait finished due to:\n");
		if (dwRv == WAIT_OBJECT_0)
		{
			// Service is stopping by user action, so unpatch
			CLEAR_AND_DEPATCH(EP_DWM_REASON_TERMINATION_BYUSER);
			break;
		}
		else if (dwRv == WAIT_OBJECT_0 + 1)
		{
			// Another user logged on, likely to have a new DWM instance, wait a bit and then recreate the process list
			OutputDebugStringW(L"ep_dwm: User logon.\n");
			if (WaitForSingleObject(ep_dwm_g_ServiceStopEvent, EP_DWM_SETUP_TIME) == WAIT_OBJECT_0)
			{
				CLEAR_AND_DEPATCH(EP_DWM_REASON_TERMINATION_BYUSER);
				break;
			}
			CLEAR(EP_DWM_REASON_NONE);
		}
		else
		{
			// One of the DWM processes has closed
			REPORT_ON_PROCESS(FALSE, dwRv - WAIT_OBJECT_0);
			CLEAR(EP_DWM_REASON_NONE);
		}
		OutputDebugStringW(L"ep_dwm: Retry (line " _T(STRINGER(__LINE__)) L").\n");
	}

	DPA_DestroyCallback(dpaPatchSites, ep_dwm_DestroyPatchSite, NULL);
	DPA_Destroy(dpaExclusionList);
	OutputDebugStringW(L"ep_dwm: Exiting service thread.\n");
	return dwRes;
}

static void WINAPI ep_dwm_ServiceCtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_SESSIONCHANGE:
		if (dwEventType == WTS_SESSION_LOGON)
		{
			OutputDebugStringW(L"ep_dwm: SERVICE_CONTROL_SESSIONCHANGE(WTS_SESSION_LOGON).\n");
			SetEvent(ep_dwm_g_ServiceSessionChangeEvent);
		}
		break;
	case SERVICE_CONTROL_STOP:
		if (ep_dwm_g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
		{
			OutputDebugStringW(L"ep_dwm: The user requested service termination, but the service is already terminating!\n");
			break;
		}
		ep_dwm_g_ServiceStatus.dwControlsAccepted = 0;
		ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		ep_dwm_g_ServiceStatus.dwWin32ExitCode = __LINE__;
		ep_dwm_g_ServiceStatus.dwCheckPoint = 5;
		if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
		{
			// error
			OutputDebugStringW(L"ep_dwm: SetServiceStatus (line " _T(STRINGER(__LINE__)) L")!\n");
		}
		OutputDebugStringW(L"ep_dwm: User requested service termination.\n");
		SetEvent(ep_dwm_g_ServiceStopEvent);
		break;
	default:
		break;
	}
}

void WINAPI ep_dwm_ServiceMain(DWORD argc, LPTSTR* argv)
{
	// Signal interested processes that this service is running
	ep_dwm_g_Service = CreateEventW(NULL, FALSE, FALSE, ep_dwm_g_wszEventName);
	if (!ep_dwm_g_Service || GetLastError() == ERROR_ALREADY_EXISTS)
	{
		if (ep_dwm_g_Service)
		{
			CloseHandle(ep_dwm_g_Service);
		}
		OutputDebugStringW(L"ep_dwm: Service is already running!\n");
		return;
	}

	// Register service with SCM
	ep_dwm_g_StatusHandle = RegisterServiceCtrlHandlerExW(ep_dwm_g_wszServiceName, ep_dwm_ServiceCtrlHandlerEx, NULL);
	if (ep_dwm_g_StatusHandle == NULL)
	{
		// error
		OutputDebugStringW(L"ep_dwm: Unable to register service with the SCM!\n");
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Inform SCM the service is starting
	ZeroMemory(&ep_dwm_g_ServiceStatus, sizeof(ep_dwm_g_ServiceStatus));
	ep_dwm_g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ep_dwm_g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
	ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ep_dwm_g_ServiceStatus.dwWin32ExitCode = __LINE__;
	ep_dwm_g_ServiceStatus.dwServiceSpecificExitCode = 0;
	ep_dwm_g_ServiceStatus.dwCheckPoint = 0;
	if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
	{
		// error
		OutputDebugStringW(L"ep_dwm: SetServiceStatus (line " _T(STRINGER(__LINE__)) L")!\n");
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Create events to signal service status
	ep_dwm_g_ServiceStopEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	ep_dwm_g_ServiceSessionChangeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
	if (!ep_dwm_g_ServiceStopEvent || !ep_dwm_g_ServiceSessionChangeEvent)
	{
		if (ep_dwm_g_ServiceStopEvent)
		{
			CloseHandle(ep_dwm_g_ServiceStopEvent);
		}
		if (ep_dwm_g_ServiceSessionChangeEvent)
		{
			CloseHandle(ep_dwm_g_ServiceSessionChangeEvent);
		}
		ep_dwm_g_ServiceStatus.dwControlsAccepted = 0;
		ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ep_dwm_g_ServiceStatus.dwWin32ExitCode = __LINE__;
		ep_dwm_g_ServiceStatus.dwCheckPoint = 1;
		if (SetServiceStatus(ep_dwm_g_StatusHandle,	&ep_dwm_g_ServiceStatus) == FALSE)
		{
			// error
			OutputDebugStringW(L"ep_dwm: SetServiceStatus (line " _T(STRINGER(__LINE__)) L")!\n");
		}
		OutputDebugStringW(L"ep_dwm: Unable to create events!\n");
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Inform SCM the service has started
	ep_dwm_g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
	ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	ep_dwm_g_ServiceStatus.dwWin32ExitCode = __LINE__;
	ep_dwm_g_ServiceStatus.dwCheckPoint = 2;
	if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
	{
		// error
		OutputDebugStringW(L"ep_dwm: SetServiceStatus (line " _T(STRINGER(__LINE__)) L")!\n");
		CloseHandle(ep_dwm_g_ServiceStopEvent);
		CloseHandle(ep_dwm_g_ServiceSessionChangeEvent);
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Create service thread
	HANDLE hServiceThread = CreateThread(NULL, 0, ep_dwm_ServiceThread, NULL, 0, NULL);
	if (!hServiceThread)
	{
		ep_dwm_g_ServiceStatus.dwControlsAccepted = 0;
		ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ep_dwm_g_ServiceStatus.dwWin32ExitCode = __LINE__;
		ep_dwm_g_ServiceStatus.dwCheckPoint = 3;
		if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
		{
			// error
			OutputDebugStringW(L"ep_dwm: SetServiceStatus (line " _T(STRINGER(__LINE__)) L")!\n");
			CloseHandle(ep_dwm_g_ServiceStopEvent);
			CloseHandle(ep_dwm_g_ServiceSessionChangeEvent);
		}
		CloseHandle(ep_dwm_g_Service);
		OutputDebugStringW(L"ep_dwm: Unable to create service thread!\n");
		return;
	}

	// Wait until our worker thread exits signaling that the service needs to stop
	WaitForSingleObject(hServiceThread, INFINITE);

	// Inform SCM the service has stopped
	ep_dwm_g_ServiceStatus.dwControlsAccepted = 0;
	ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	GetExitCodeThread(hServiceThread, &ep_dwm_g_ServiceStatus.dwWin32ExitCode);
	ep_dwm_g_ServiceStatus.dwCheckPoint = 4;
	if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
	{
		// error
		OutputDebugStringW(L"ep_dwm: SetServiceStatus (line " _T(STRINGER(__LINE__)) L")!\n");
	}

	CloseHandle(hServiceThread);
	CloseHandle(ep_dwm_g_ServiceStopEvent);
	CloseHandle(ep_dwm_g_ServiceSessionChangeEvent);
	CloseHandle(ep_dwm_g_Service);

	OutputDebugStringW(L"ep_dwm: Service has terminated.\n");
	return;
}

BOOL WINAPI ep_dwm_StartService(LPWSTR wszServiceName, LPWSTR wszEventName)
{
	ep_dwm_g_wszServiceName = wszServiceName;
	ep_dwm_g_wszEventName = wszEventName;

	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{wszServiceName, (LPSERVICE_MAIN_FUNCTION)ep_dwm_ServiceMain},
		{NULL, NULL}
	};

	return StartServiceCtrlDispatcherW(ServiceTable);
}

#ifndef EP_DWM_NO_WINMAIN
int WINAPI wWinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR lpCmdLine,
	_In_ int nShowCmd
)
{
	int argc = 0;
	LPWSTR* wargv = CommandLineToArgvW(lpCmdLine, &argc);
	ZeroMemory(lpCmdLine, sizeof(WCHAR) * wcslen(lpCmdLine));
	if (argc >= 2)
	{
		ep_dwm_StartService(wargv[0], wargv[1]);
		LocalFree(wargv);
	}
	return 0;
}
#endif
