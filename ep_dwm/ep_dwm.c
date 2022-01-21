#include "ep_dwm.h"

LPWSTR                ep_dwm_g_wszServiceName;
LPWSTR                ep_dwm_g_wszEventName;
SERVICE_STATUS        ep_dwm_g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE ep_dwm_g_StatusHandle = NULL;
HANDLE                ep_dwm_g_Service = INVALID_HANDLE_VALUE;
HANDLE                ep_dwm_g_ServiceStopEvent = INVALID_HANDLE_VALUE;
HANDLE                ep_dwm_g_ServiceSessionChangeEvent = INVALID_HANDLE_VALUE;
DWORD				  ep_dwm_g_ExitCode = 0;
#define				  EP_DWM_NUM_EVENTS 2
#define               EP_DWM_SETUP_TIME 2000
#define               EP_DWM_GRACE_TIME 5000
#define				  EP_DWM_GROW 10
#define               EP_DWM_MAX_NUM_MODULES 200
#define               EP_DWM_PATCH_ERROR_MASK 0x2710
#define				  EP_DWM_PATCH_ERROR_SUCCESS 0
#define				  EP_DWM_PATCH_ERROR_NO_MODULES 1
#define               EP_DWM_PATCH_ERROR_CANNOT_CHANGE_MEMORY_PROTECTION 2
#define               EP_DWM_PATCH_ERROR_UNSUITABLE_PATCH 3
#define				  EP_DWM_PATCH_ERROR_REMOTE_WRITE_FAILED 4
#define               EP_DWM_PATCH_ERROR_NO_UDWM 5
#define               EP_DWM_PATCH_ERROR_NO_MEMORY 6
char ep_dwm_pattern_data[1][6] = { {0x0F, 0x57, 0xF6, 0xF3, 0x48, 0x0F} };
// xorps xmm6, xmm6
// cvtsi2ss xmm6, rax
unsigned int ep_dwm_pattern_length[1] = { 6 };
// this patch always replaces 4 bytes coresponding to a "mov eax, [reg+offh+arg]" operation
char ep_dwm_patch_data[1][4] = { {0x31, 0xC0, 0xFF, 0xC0} };
// xor eax, eax
// inc eax
unsigned int ep_dwm_patch_length[1] = { 4 };

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
	DWORD dwRes = EP_DWM_PATCH_ERROR_SUCCESS;

	HMODULE hModule = LoadLibraryW(wszUDWMPath, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (!hModule)
	{
		return EP_DWM_PATCH_ERROR_NO_UDWM;
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
						pCandidate = ep_memmem(
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
						if (!bContains)
						{
							DPA_AppendPtr(dpaOffsetList, pCandidate - hModule);
							char* pOldCode = malloc(ep_dwm_patch_length[0] * sizeof(char));
							if (!pOldCode)
							{
								for (unsigned int k = 0; k < DPA_GetPtrCount(dpaPatchList); ++k)
								{
									free(DPA_FastGetPtr(dpaPatchList, k));
								}
								return EP_DWM_PATCH_ERROR_NO_MEMORY;
							}
							memcpy(pOldCode, pCandidate - ep_dwm_patch_length[0], ep_dwm_patch_length[0]);
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

	return dwRes;
}

static DWORD ep_dwm_PatchProcess(WCHAR* wszUDWMPath, HANDLE hProcess, HDPA dpaOffsetList, HDPA dpaOldCodeList)
{
	DWORD dwRes = EP_DWM_PATCH_ERROR_SUCCESS;

	MODULEENTRY32 me32;
	ZeroMemory(&me32, sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(MODULEENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
	if (!hSnapshot)
	{
		return EP_DWM_PATCH_ERROR_NO_MODULES;
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
					if (!VirtualProtectEx(hProcess, me32.modBaseAddr + (uintptr_t)DPA_FastGetPtr(dpaOffsetList, j) - ep_dwm_patch_length[0], ep_dwm_patch_length[0], PAGE_EXECUTE_READWRITE, &dwOldProtect))
					{
						dwRes = EP_DWM_PATCH_ERROR_CANNOT_CHANGE_MEMORY_PROTECTION;
					}
					else
					{
						WriteProcessMemory(hProcess, me32.modBaseAddr + (uintptr_t)DPA_FastGetPtr(dpaOffsetList, j) - ep_dwm_patch_length[0], dpaOldCodeList ? DPA_FastGetPtr(dpaOldCodeList, j) : ep_dwm_patch_data[0], ep_dwm_patch_length[0], &dwNumberOfBytesWritten);
						if (!dwNumberOfBytesWritten || dwNumberOfBytesWritten != ep_dwm_patch_length[0])
						{
							dwRes = EP_DWM_PATCH_ERROR_REMOTE_WRITE_FAILED;
						}
						VirtualProtectEx(hProcess, me32.modBaseAddr + (uintptr_t)DPA_FastGetPtr(dpaOffsetList, j) - ep_dwm_patch_length[0], ep_dwm_patch_length[0], dwOldProtect, &dwOldProtect);
					}
				}
				break;
			}
		} while (Module32NextW(hSnapshot, &me32) == TRUE && dwRes == EP_DWM_PATCH_ERROR_SUCCESS);
	}
	CloseHandle(hSnapshot);

	return dwRes;
}

static DWORD WINAPI ep_dwm_ServiceThread(LPVOID lpUnused)
{
	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe32;
	HDPA dpaExclusionList = NULL;
	HDPA dpaHandlesList = NULL;
	HDPA dpaOffsetList = NULL;
	HDPA dpaOldCodeList = NULL;

	WCHAR wszDWMPath[MAX_PATH];
	GetSystemDirectoryW(wszDWMPath, MAX_PATH);
	wcscat_s(wszDWMPath, MAX_PATH, L"\\dwm.exe");

	WCHAR wszUDWMPath[MAX_PATH];
	GetSystemDirectoryW(wszUDWMPath, MAX_PATH);
	wcscat_s(wszUDWMPath, MAX_PATH, L"\\uDWM.dll");

	dpaOffsetList = DPA_Create(EP_DWM_GROW);
	if (!dpaOffsetList)
	{
		return 0;
	}

	dpaOldCodeList = DPA_Create(EP_DWM_GROW);
	if (!dpaOldCodeList)
	{
		return 0;
	}

	if (ep_dwm_DeterminePatchAddresses(wszUDWMPath, dpaOffsetList, dpaOldCodeList))
	{
		return 0;
	}

	dpaExclusionList = DPA_Create(EP_DWM_NUM_EVENTS);
	if (!dpaExclusionList)
	{
		return 0;
	}
	DPA_AppendPtr(dpaExclusionList, ep_dwm_g_ServiceStopEvent);
	DPA_AppendPtr(dpaExclusionList, ep_dwm_g_ServiceSessionChangeEvent);

	while (TRUE)
	{
		dpaHandlesList = DPA_Create(EP_DWM_GROW);
		if (!dpaHandlesList)
		{
			break;
		}

		for (unsigned int i = 0; i < DPA_GetPtrCount(dpaExclusionList); ++i)
		{
			DPA_AppendPtr(dpaHandlesList, DPA_FastGetPtr(dpaExclusionList, i));
		}

		hSnapshot = NULL;
		ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
		pe32.dwSize = sizeof(PROCESSENTRY32);
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (!hSnapshot)
		{
			DPA_Destroy(dpaHandlesList);
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

		if (WaitForSingleObject(ep_dwm_g_ServiceStopEvent, EP_DWM_SETUP_TIME) == WAIT_OBJECT_0)
		{
			DPA_DestroyCallback(dpaHandlesList, ep_dwm_DestroyHandle, dpaExclusionList);
			break;
		}

		for (unsigned int i = EP_DWM_NUM_EVENTS; i < DPA_GetPtrCount(dpaHandlesList); ++i)
		{
			DWORD dwStatus = ep_dwm_PatchProcess(wszUDWMPath, DPA_FastGetPtr(dpaHandlesList, i), dpaOffsetList, NULL);
			if (dwStatus != EP_DWM_PATCH_ERROR_SUCCESS)
			{
				ep_dwm_g_ExitCode = EP_DWM_PATCH_ERROR_MASK & dwStatus;
			}
		}

		if (WaitForSingleObject(ep_dwm_g_ServiceStopEvent, EP_DWM_GRACE_TIME) == WAIT_OBJECT_0)
		{
			for (unsigned int i = EP_DWM_NUM_EVENTS; i < DPA_GetPtrCount(dpaHandlesList); ++i)
			{
				DWORD dwStatus = ep_dwm_PatchProcess(wszUDWMPath, DPA_FastGetPtr(dpaHandlesList, i), dpaOffsetList, dpaOldCodeList);
				if (dwStatus != EP_DWM_PATCH_ERROR_SUCCESS)
				{
					ep_dwm_g_ExitCode = EP_DWM_PATCH_ERROR_MASK & dwStatus;
				}
			}
			DPA_DestroyCallback(dpaHandlesList, ep_dwm_DestroyHandle, dpaExclusionList);
			break;
		}

		BOOL bPatchHasCrashedDWM = FALSE;
		for (unsigned int i = EP_DWM_NUM_EVENTS; i < DPA_GetPtrCount(dpaHandlesList); ++i)
		{
			if (WaitForSingleObject(DPA_FastGetPtr(dpaHandlesList, i), 0) == WAIT_OBJECT_0)
			{
				bPatchHasCrashedDWM = TRUE;
				break;
			}
		}
		if (bPatchHasCrashedDWM)
		{
			break;
		}

		DWORD dwRes = WaitForMultipleObjects(DPA_GetPtrCount(dpaHandlesList), DPA_GetPtrPtr(dpaHandlesList), FALSE, INFINITE);
		if (dwRes == WAIT_OBJECT_0)
		{
			for (unsigned int i = EP_DWM_NUM_EVENTS; i < DPA_GetPtrCount(dpaHandlesList); ++i)
			{
				DWORD dwStatus = ep_dwm_PatchProcess(wszUDWMPath, DPA_FastGetPtr(dpaHandlesList, i), dpaOffsetList, dpaOldCodeList);
				if (dwStatus != EP_DWM_PATCH_ERROR_SUCCESS)
				{
					ep_dwm_g_ExitCode = EP_DWM_PATCH_ERROR_MASK & dwStatus;
				}
			}
		}
		DPA_DestroyCallback(dpaHandlesList, ep_dwm_DestroyHandle, dpaExclusionList);
		if (dwRes == WAIT_OBJECT_0)
		{
			break;
		}
	}

	DPA_DestroyCallback(dpaOldCodeList, ep_dwm_DestroyOldCode, NULL);
	DPA_Destroy(dpaOffsetList);
	DPA_Destroy(dpaExclusionList);

	return 0;
}

static void WINAPI ep_dwm_ServiceCtrlHandlerEx(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
	switch (dwControl)
	{
	case SERVICE_CONTROL_SESSIONCHANGE:
		SetEvent(ep_dwm_g_ServiceSessionChangeEvent);
	case SERVICE_CONTROL_STOP:
		if (ep_dwm_g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
		{
			break;
		}
		ep_dwm_g_ServiceStatus.dwControlsAccepted = 0;
		ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		ep_dwm_g_ServiceStatus.dwWin32ExitCode = 0;
		ep_dwm_g_ServiceStatus.dwCheckPoint = 4;
		if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
		{
			// error
		}
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
		return;
	}

	// Register service with SCM
	ep_dwm_g_StatusHandle = RegisterServiceCtrlHandlerExW(ep_dwm_g_wszServiceName, ep_dwm_ServiceCtrlHandlerEx, NULL);
	if (ep_dwm_g_StatusHandle == NULL)
	{
		// error
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Inform SCM the service is starting
	ZeroMemory(&ep_dwm_g_ServiceStatus, sizeof(ep_dwm_g_ServiceStatus));
	ep_dwm_g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ep_dwm_g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
	ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ep_dwm_g_ServiceStatus.dwWin32ExitCode = NO_ERROR;
	ep_dwm_g_ServiceStatus.dwServiceSpecificExitCode = 0;
	ep_dwm_g_ServiceStatus.dwCheckPoint = 0;
	if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
	{
		// error
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
		ep_dwm_g_ServiceStatus.dwWin32ExitCode = GetLastError();
		ep_dwm_g_ServiceStatus.dwCheckPoint = 1;
		if (SetServiceStatus(
			ep_dwm_g_StatusHandle,
			&ep_dwm_g_ServiceStatus
		) == FALSE)
		{
			// error
		}
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Inform SCM the service has started
	ep_dwm_g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	ep_dwm_g_ServiceStatus.dwWin32ExitCode = 0;
	ep_dwm_g_ServiceStatus.dwCheckPoint = 0;
	if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
	{
		CloseHandle(ep_dwm_g_ServiceStopEvent);
		CloseHandle(ep_dwm_g_ServiceSessionChangeEvent);
		// error
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Create service thread
	HANDLE hServiceThread = CreateThread(NULL, 0, ep_dwm_ServiceThread, NULL, 0, NULL);
	if (!hServiceThread)
	{
		ep_dwm_g_ServiceStatus.dwControlsAccepted = 0;
		ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ep_dwm_g_ServiceStatus.dwWin32ExitCode = GetLastError();
		ep_dwm_g_ServiceStatus.dwCheckPoint = 1;
		if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
		{
			CloseHandle(ep_dwm_g_ServiceStopEvent);
			CloseHandle(ep_dwm_g_ServiceSessionChangeEvent);
			// error
		}
		CloseHandle(ep_dwm_g_Service);
		return;
	}

	// Wait until our worker thread exits signaling that the service needs to stop
	WaitForSingleObject(hServiceThread, INFINITE);

	CloseHandle(hServiceThread);
	CloseHandle(ep_dwm_g_ServiceStopEvent);
	CloseHandle(ep_dwm_g_ServiceSessionChangeEvent);

	// Inform SCM the service has stopped
	ep_dwm_g_ServiceStatus.dwControlsAccepted = 0;
	ep_dwm_g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	ep_dwm_g_ServiceStatus.dwWin32ExitCode = ep_dwm_g_ExitCode;
	ep_dwm_g_ServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(ep_dwm_g_StatusHandle, &ep_dwm_g_ServiceStatus) == FALSE)
	{
		// error
	}

	CloseHandle(ep_dwm_g_Service);
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

int ep_dwm_StartService2(HWND hWnd, HINSTANCE hInstance, LPSTR lpszCmdLine, int nCmdShow)
{
	ep_dwm_StartService(L"ep_dwm_Service_{957A01C5-676F-4958-8F64-829FCF4C82DA}", L"Global\\ep_dwm_Service_{957A01C5-676F-4958-8F64-829FCF4C82DA}");
}

#ifndef EP_DWM_NO_DLLMAIN
BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hinstDLL);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
#endif
