#ifndef _H_DWM_H_
#define _H_DWM_H_
#pragma comment(linker,"\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#include <Windows.h>
#include <TlHelp32.h>
#include <dpa_dsa.h>
#include <Psapi.h>
#pragma comment(lib, "Comctl32.lib")
#include <tchar.h>
#pragma comment(lib, "version.lib")

void WINAPI ep_dwm_ServiceMain(DWORD argc, LPTSTR* argv);
BOOL ep_dwm_StartService(LPWSTR wszServiceName, LPWSTR wszEventName);
inline void* ep_dwm_memmem(void* haystack, size_t haystacklen, void* needle, size_t needlelen)
{
    const char* text = (const char*)haystack;
    const char* pattern = (const char*)needle;
    const char* rv = NULL;

    size_t* out = calloc(needlelen, sizeof(size_t));
    if (!out)
    {
        return NULL;
    }
    size_t j, i;

    j = 0, i = 1;
    while (i < needlelen) {
        if (text[j] != text[i])
        {
            if (j > 0)
            {
                j = out[j - 1];
                continue;
            }
            else j--;
        }
        j++;
        out[i] = j;
        i++;
    }

    i = 0, j = 0;
    for (i = 0; i <= haystacklen; i++) {
        if (text[i] == pattern[j]) {
            j++;
            if (j == needlelen) {
                rv = text + (int)(i - needlelen + 1);
                break;
            }
        }
        else {
            if (j != 0) {
                j = out[j - 1];
                i--;
            }
        }
    }

    free(out);
    return rv;
}

BOOL ep_dwm_IsWindows11Version22H2OrHigher()
{
    // Avoid manifesting the exe
    // https://stackoverflow.com/questions/25986331/how-to-determine-windows-version-in-future-proof-way

    static const wchar_t kernel32[] = L"\\kernel32.dll";
    wchar_t* path = NULL;
    void* ver = NULL, * block;
    UINT n;
    BOOL r;
    DWORD versz, blocksz;
    VS_FIXEDFILEINFO* vinfo;

    path = malloc(sizeof(*path) * MAX_PATH);
    if (!path)
        return FALSE;

    n = GetSystemDirectoryW(path, MAX_PATH);
    if (n >= MAX_PATH || n == 0 ||
        n > MAX_PATH - sizeof(kernel32) / sizeof(*kernel32))
        return FALSE;
    memcpy(path + n, kernel32, sizeof(kernel32));

    versz = GetFileVersionInfoSizeW(path, NULL);
    if (versz == 0)
        return FALSE;
    ver = malloc(versz);
    if (!ver)
        return FALSE;
    r = GetFileVersionInfoW(path, 0, versz, ver);
    if (!r)
        return FALSE;
    r = VerQueryValueW(ver, L"\\", &block, &blocksz);
    if (!r || blocksz < sizeof(VS_FIXEDFILEINFO))
        return FALSE;
    vinfo = (VS_FIXEDFILEINFO*)block;
    //printf(
    //    "Windows version: %d.%d.%d.%d",
    //    (int)HIWORD(vinfo->dwProductVersionMS), // 10
    //    (int)LOWORD(vinfo->dwProductVersionMS), // 0
    //    (int)HIWORD(vinfo->dwProductVersionLS), // 22000
    //    (int)LOWORD(vinfo->dwProductVersionLS));// 708
    free(path);
    free(ver);
    return ((int)HIWORD(vinfo->dwProductVersionLS) >= 22621);
}
#endif
