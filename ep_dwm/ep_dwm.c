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
char ep_dwm_pattern_data[1][20] = { {0x0F, 0x57, 0xF6, 0xF3, 0x48, 0x0F} };
// xorps xmm6, xmm6
// cvtsi2ss xmm6, rax
unsigned int ep_dwm_pattern_length[1] = { 6 };
// this patch always replaces 4 bytes coresponding to a "mov eax, [reg+offh+arg]" operation
char ep_dwm_patch_data[1][20] = { {0x31, 0xC0, 0xFF, 0xC0} };
// xor eax, eax
// inc eax
unsigned int ep_dwm_patch_length[1] = { 4 };

unsigned int ep_dwm_expected_matches = 4;

unsigned int ep_dwm_strategy = 0;
int ep_dwm_strategy_1_order = -1;

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
		ep_dwm_PatchProcess(wszUDWMPath, DPA_FastGetPtr(dpaHandlesList, i), dpaOffsetList, dpaOldCodeList); \
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

static int ep_dwm_DestroyOldCode(void* p, void* pUnused)
{
	free(p);
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

static DWORD ep_dwm_DeterminePatchAddresses(WCHAR* wszUDWMPath, HDPA dpaOffsetList, HDPA dpaPatchList)
{
	DWORD dwRes = 0;

	HMODULE hModule = LoadLibraryW(wszUDWMPath, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (!hModule)
	{
		OutputDebugStringW(L"ep_dwm: Failed (LoadLibraryW) (line " _T(STRINGER(__LINE__)) L")!\n");
		return __LINE__;
	}

	void* p = NULL;
	uintptr_t diff = 0;
	PIMAGE_DOS_HEADER dosHeader = hModule;
	if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)((u_char*)dosHeader + dosHeader->e_lfanew);
		if (ntHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
			for (unsigned int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
			{
				if ((section->Characteristics & IMAGE_SCN_CNT_CODE) && section->SizeOfRawData)
				{
					char* pCandidate = NULL;
					while (TRUE)
					{
						pCandidate = ep_dwm_memmem(
							!pCandidate ? hModule + section->VirtualAddress : pCandidate,
							!pCandidate ? section->SizeOfRawData : (uintptr_t)section->SizeOfRawData - (uintptr_t)(pCandidate - (hModule + section->VirtualAddress)),
							ep_dwm_pattern_data[0],
							ep_dwm_pattern_length[0]
						);
						if (!pCandidate)
						{
							break;
						}
						BOOL bContains = FALSE;
						for (unsigned j = 0; j < DPA_GetPtrCount(dpaOffsetList); ++j)
						{
							if (DPA_FastGetPtr(dpaOffsetList, j) == pCandidate - hModule)
							{
								bContains = TRUE;
								break;
							}
						}
						BOOL bPassedCheck = TRUE;
						if (ep_dwm_strategy == 1)
						{
							UINT32 offset = *(UINT32*)(pCandidate + 4);
							UINT32 value = *(UINT32*)(pCandidate + offset + 0x8);
							if (!(value == 0x41000000 /* 8.0 */ || value == 0x40800000 /* 4.0 */)) bPassedCheck = FALSE;
						}
						if (bPassedCheck && !bContains)
						{
							if (ep_dwm_strategy == 1 && (*(char*)(pCandidate + 8) & 0xFF) == 0x0f && (*(char*)(pCandidate + 9) & 0xFF) == 0x28 && (*(char*)(pCandidate + 10) & 0xFF) == 0xc6) ep_dwm_strategy_1_order = (DPA_GetPtrCount(dpaOffsetList) == 0 ? 0 : 1);
							DPA_AppendPtr(dpaOffsetList, pCandidate - hModule);
							char* pOldCode = malloc(ep_dwm_patch_length[0] * sizeof(char));
							if (!pOldCode)
							{
								for (unsigned int k = 0; k < DPA_GetPtrCount(dpaPatchList); ++k)
								{
									free(DPA_FastGetPtr(dpaPatchList, k));
								}
								return __LINE__;
							}
							int offset = (0 - ep_dwm_patch_length[0]);
							if (ep_dwm_strategy == 1) offset = 0;
							memcpy(pOldCode, pCandidate + offset, ep_dwm_patch_length[0]);
							DPA_AppendPtr(dpaPatchList, pOldCode);
						}
						pCandidate += ep_dwm_pattern_length[0];
						if (pCandidate > hModule + section->VirtualAddress + section->SizeOfRawData)
						{
							break;
						}
					}
				}
			}
		}
	}

	FreeLibrary(hModule);

	if (DPA_GetPtrCount(dpaOffsetList) != DPA_GetPtrCount(dpaPatchList))
	{
		OutputDebugStringW(L"ep_dwm: Different number of offsets and places to patch!\n");
		dwRes == __LINE__;
	}
	if (DPA_GetPtrCount(dpaOffsetList) == 0)
	{
		OutputDebugStringW(L"ep_dwm: Unable to identify patch area!\n");
		dwRes == __LINE__;
	}

	return dwRes;
}

static DWORD ep_dwm_PatchProcess(WCHAR* wszUDWMPath, HANDLE hProcess, HDPA dpaOffsetList, HDPA dpaOldCodeList)
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
			if (!_wcsicmp(me32.szExePath, wszUDWMPath))
			{
				for (unsigned int j = 0; j < DPA_GetPtrCount(dpaOffsetList, j); ++j)
				{
					DWORD dwOldProtect = 0;
					SIZE_T dwNumberOfBytesWritten = 0;
					int offset = (0 - ep_dwm_patch_length[0]);
					if (ep_dwm_strategy == 1) offset = 0;
					if (ep_dwm_strategy == 1 && (ep_dwm_strategy_1_order == 0 ? (j == 0 || j == 1) : (j == 2 || j == 3))) {
						ep_dwm_patch_data[0][0] = 0xB0; // change working register to al/rax
						ep_dwm_patch_data[0][6] = 0xF0;
					}
					if (!VirtualProtectEx(hProcess, me32.modBaseAddr + (uintptr_t)DPA_FastGetPtr(dpaOffsetList, j) + offset, ep_dwm_patch_length[0], PAGE_EXECUTE_READWRITE, &dwOldProtect))
					{
						OutputDebugStringW(L"ep_dwm: Failed (VirtualProtectEx) (line " _T(STRINGER(__LINE__)) L")!\n");
						dwRes = __LINE__;
					}
					else
					{
						WriteProcessMemory(hProcess, me32.modBaseAddr + (uintptr_t)DPA_FastGetPtr(dpaOffsetList, j) + offset, dpaOldCodeList ? DPA_FastGetPtr(dpaOldCodeList, j) : ep_dwm_patch_data[0], ep_dwm_patch_length[0], &dwNumberOfBytesWritten);
						if (!dwNumberOfBytesWritten || dwNumberOfBytesWritten != ep_dwm_patch_length[0])
						{
							OutputDebugStringW(L"ep_dwm: Failed (WriteProcessMemory) (line " _T(STRINGER(__LINE__)) L")!\n");
							dwRes = __LINE__;
						}
						VirtualProtectEx(hProcess, me32.modBaseAddr + (uintptr_t)DPA_FastGetPtr(dpaOffsetList, j) + offset, ep_dwm_patch_length[0], dwOldProtect, &dwOldProtect);
					}
					if (ep_dwm_strategy == 1 && (ep_dwm_strategy_1_order == 0 ? (j == 0 || j == 1) : (j == 2 || j == 3))) {
						ep_dwm_patch_data[0][0] = 0xB1; // revert change to register cl/rcx
						ep_dwm_patch_data[0][6] = 0xF1;
					}
				}
				break;
			}
		} while (Module32NextW(hSnapshot, &me32) == TRUE && dwRes == 0);
	}
	CloseHandle(hSnapshot);

	return dwRes;
}

static DWORD WINAPI ep_dwm_ServiceThread(LPVOID lpUnused)
{
	DWORD dwRes = __LINE__;

	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32;
	HDPA dpaExclusionList = NULL;
	HDPA dpaHandlesList = NULL;
	HDPA dpaOffsetList = NULL;
	HDPA dpaOldCodeList = NULL;

	ep_dwm_strategy = (ep_dwm_IsWindows11Version22H2OrHigher() ? 1 : 0);
	if (ep_dwm_strategy == 1)
	{
		ep_dwm_pattern_data[0][0] = 0xF3; // movss xmm6, ...
		ep_dwm_pattern_data[0][1] = 0x0F;
		ep_dwm_pattern_data[0][2] = 0x10;
		ep_dwm_pattern_data[0][3] = 0x35;
		ep_dwm_pattern_length[0] = 4;
		ep_dwm_patch_data[0][0] = 0xB1; // mov cl, 1
		ep_dwm_patch_data[0][1] = 0x01;
		ep_dwm_patch_data[0][2] = 0xF3; // cvtsi2ss xmm6,rcx
		ep_dwm_patch_data[0][3] = 0x48;
		ep_dwm_patch_data[0][4] = 0x0F;
		ep_dwm_patch_data[0][5] = 0x2A;
		ep_dwm_patch_data[0][6] = 0xF1;
		ep_dwm_patch_data[0][7] = 0x90;
		ep_dwm_patch_length[0] = 8;
	}

	WCHAR wszDWMPath[MAX_PATH];
	GetSystemDirectoryW(wszDWMPath, MAX_PATH);
	wcscat_s(wszDWMPath, MAX_PATH, L"\\dwm.exe");

	WCHAR wszUDWMPath[MAX_PATH];
	GetSystemDirectoryW(wszUDWMPath, MAX_PATH);
	wcscat_s(wszUDWMPath, MAX_PATH, L"\\uDWM.dll");

	dpaOffsetList = DPA_Create(EP_DWM_GROW);
	if (!dpaOffsetList)
	{
		OutputDebugStringW(L"ep_dwm: Failed (DPA_Create) (line " _T(STRINGER(__LINE__)) L")!\n");
		dwRes = __LINE__;
		return dwRes;
	}

	dpaOldCodeList = DPA_Create(EP_DWM_GROW);
	if (!dpaOldCodeList)
	{
		OutputDebugStringW(L"ep_dwm: Failed (DPA_Create) (line " _T(STRINGER(__LINE__)) L")!\n");
		dwRes = __LINE__;
		return dwRes;
	}

	if (dwRes = ep_dwm_DeterminePatchAddresses(wszUDWMPath, dpaOffsetList, dpaOldCodeList))
	{
		return dwRes;
	}

	dpaExclusionList = DPA_Create(EP_DWM_NUM_EVENTS);
	if (!dpaExclusionList)
	{
		dwRes = __LINE__;
		OutputDebugStringW(L"ep_dwm: Failed (DPA_Create) (line " _T(STRINGER(__LINE__)) L")!\n");
		return dwRes;
	}
	DPA_AppendPtr(dpaExclusionList, ep_dwm_g_ServiceStopEvent);
	DPA_AppendPtr(dpaExclusionList, ep_dwm_g_ServiceSessionChangeEvent);

	while (DPA_GetPtrCount(dpaOffsetList) == ep_dwm_expected_matches)
	{
		DWORD dwFailedNum = 0;

		dpaHandlesList = DPA_Create(EP_DWM_GROW);
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
		hSnapshot = NULL;
		ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
		pe32.dwSize = sizeof(PROCESSENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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
		if (DPA_GetPtrCount(dpaHandlesList) == 0)
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
			if (ep_dwm_PatchProcess(wszUDWMPath, DPA_FastGetPtr(dpaHandlesList, i), dpaOffsetList, NULL))
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

	DPA_DestroyCallback(dpaOldCodeList, ep_dwm_DestroyOldCode, NULL);
	DPA_Destroy(dpaOffsetList);
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
