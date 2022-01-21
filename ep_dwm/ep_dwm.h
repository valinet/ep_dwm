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

#ifndef EP_DWM_NO_EXPORTS
__declspec(dllexport) 
#endif
void WINAPI ep_dwm_ServiceMain(DWORD argc, LPTSTR* argv);
#ifndef EP_DWM_NO_EXPORTS
__declspec(dllexport)
#endif
BOOL ep_dwm_StartService(LPWSTR wszServiceName, LPWSTR wszEventName);
#ifndef EP_DWM_NO_EXPORTS
__declspec(dllexport)
#endif
int ep_dwm_StartService2(HWND hWnd, HINSTANCE hInstance, LPSTR lpszCmdLine, int nCmdShow);
inline void* ep_memmem(void* haystack, size_t haystacklen, void* needle, size_t needlelen)
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
#endif