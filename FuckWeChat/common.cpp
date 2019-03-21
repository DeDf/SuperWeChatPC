
#include "common.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Version.lib")

// return : pData (Need Free)
BYTE *GetFileVersion(PWCHAR pwchFilePath, VS_FIXEDFILEINFO **ppVerInfo)
{
    BYTE *pData = NULL;

    if (ppVerInfo)
        *ppVerInfo = NULL;

    if (PathFileExistsW(pwchFilePath))
    {
        DWORD dwTemp;
        DWORD dwSize = GetFileVersionInfoSizeW(pwchFilePath, &dwTemp);
        if (dwSize)
        {
            pData = (BYTE *)malloc(dwSize + 1);
            if (pData)
            {
                if (GetFileVersionInfoW(pwchFilePath, 0, dwSize, pData))
                {
                    UINT uLen;

                    if (VerQueryValueW(pData, L"\\", (PVOID *)ppVerInfo, &uLen))
                    {
                        DWORD verMS = (*ppVerInfo)->dwFileVersionMS;
                        DWORD verLS = (*ppVerInfo)->dwFileVersionLS;
                        WORD major = HIWORD(verMS);
                        WORD minor = LOWORD(verMS);
                        WORD build = HIWORD(verLS);
                        WORD rever = LOWORD(verLS);

                        printf("%d.%d.%d.%d\n", major, minor, build, rever);
                    }
                }
            }
        }
    }

    return pData;
}

BOOL
IsSupportedWxVersion (
    P_WX_VERSION pWXVer,
    INT ver_count,
    ULONG* pOffset,
    BYTE* orig_code,
    WORD* orig_code_count,
    BYTE* fake_code,
    WORD* fake_code_count
    )
{
    BOOL bRet = FALSE;
    WCHAR pwchDllPath[MAX_PATH];

    GetModuleFileNameW(NULL, pwchDllPath, _countof(pwchDllPath));
    PathRemoveFileSpecW(pwchDllPath);
    PathAppendW(pwchDllPath, L_WECHATWINDLL);

    VS_FIXEDFILEINFO *pVersion;
    BYTE *pData = GetFileVersion(pwchDllPath, &pVersion);
    if (pData)
    {
        DWORD verMS = pVersion->dwFileVersionMS;
        DWORD verLS = pVersion->dwFileVersionLS;
        WORD major = HIWORD(verMS);
        WORD minor = LOWORD(verMS);
        WORD build = HIWORD(verLS);
        WORD rever = LOWORD(verLS);

        for (int i = 0; i < ver_count; i++)
        {
            if (major == pWXVer[i].major &&
                minor == pWXVer[i].minor &&
                build == pWXVer[i].build &&
                rever == pWXVer[i].rever)
            {
                if (pOffset) {
                    *pOffset = pWXVer[i].offset;
                }

                if (orig_code) {
                    memcpy(orig_code, pWXVer[i].OrgCode, pWXVer[i].OrgCodeLen);
                }
                if (orig_code_count) {
                    *orig_code_count = pWXVer[i].OrgCodeLen;
                }

                if (fake_code) {
                    memcpy(fake_code, pWXVer[i].PatchCode, pWXVer[i].PatchCodeLen);
                }
                if (fake_code_count) {
                    *fake_code_count = pWXVer[i].PatchCodeLen;
                }
                
                bRet = TRUE;
                break;
            }
        }

        free(pData);
    }

    return bRet;
}

void Patch(PVOID addr, DWORD size, PVOID code)
{
    DWORD lpOldPro = 0;

    if (VirtualProtect((LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &lpOldPro))
    {
        memcpy((char*)addr, (char*)code, size);

        VirtualProtect((LPVOID)addr, size, lpOldPro, &lpOldPro);
    }
}