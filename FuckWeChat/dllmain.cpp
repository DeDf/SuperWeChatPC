
#include "common.h"

VOID Init()
{
    //HKEY_CURRENT_USER\Software\Tencent\WeChat InstallPath = xx
    HKEY hKey = NULL;
    if (!RegOpenKeyW(HKEY_CURRENT_USER, L"Software\\Tencent\\WeChat", &hKey))
    {
        DWORD Type = REG_SZ;
        WCHAR wchFileName[MAX_PATH];
        DWORD cbData = sizeof(wchFileName);

        if (!RegQueryValueExW(hKey, L"InstallPath", 0, &Type, (LPBYTE)wchFileName, &cbData))
        {
            PathAppendW(wchFileName, L_WECHATWINDLL);
        }

        CloseHandle(hKey);
    }
}

VOID Uninit()
{
}

BOOL APIENTRY DllMain( HMODULE hModule,
                      DWORD  ul_reason_for_call,
                      LPVOID lpReserved
                      )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        PatchRevokeMsg();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}