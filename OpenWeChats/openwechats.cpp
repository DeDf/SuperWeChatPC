#include <stdio.h>
#include "openwechats.h"
#include <TlHelp32.h>

ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
NTQUERYOBJECT NtQueryObject;

//进程提权
BOOL ElevatePrivileges()
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tkp;
    tkp.PrivilegeCount = 1;
    LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);

    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        return FALSE;
    }

    return TRUE;
}

HANDLE DuplicateHandleEx(DWORD pid, HANDLE h, DWORD flags)
{
    HANDLE hHandle = NULL;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc)
    {
        if (!DuplicateHandle(hProc,
            h, GetCurrentProcess(),
            &hHandle, 0, FALSE, flags))
        {
            hHandle = NULL;
        }

        CloseHandle(hProc);
    }

    return hHandle;
}

int GetProcIds(LPCWSTR Name, DWORD* pids)
{
    int num = 0;
    if (pids)
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap)
        {
            PROCESSENTRY32 pe32 = { sizeof(pe32) };
            if (Process32First(hSnap, &pe32))
            {
                do
                {
                    if (!_wcsicmp(Name, pe32.szExeFile))
                    {
                        pids[num++] = pe32.th32ProcessID;
                    }
                } while (Process32Next(hSnap, &pe32));
            }
            CloseHandle(hSnap);
        }
    }

    return num;
}

BOOL IsTargetPid(DWORD Pid, DWORD* Pids, ULONG count)
{
    for (ULONG i = 0; i < count; i++)
    {
        if (Pid == Pids[i])
        {
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS PatchWeChat()
{
    int ret = -1;
    NTSTATUS status;

    ElevatePrivileges(); 

    DWORD Pids[100] = { 0 };
    DWORD WeCharProcCnt = GetProcIds(L"WeChat.exe", Pids);
    if (WeCharProcCnt == 0)
    {
        return ret;
    }

    DWORD dwSize = 0x1000;
    PVOID pbuffer = VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
    if (pbuffer)
    {
        status = ZwQuerySystemInformation(SystemHandleInformation, pbuffer, dwSize, &dwSize);
        if (status)
        {
            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                VirtualFree(pbuffer, 0, MEM_RELEASE);
                pbuffer = VirtualAlloc(NULL, dwSize * 2, MEM_COMMIT, PAGE_READWRITE);

                if (pbuffer)
                {
                    status = ZwQuerySystemInformation(SystemHandleInformation, pbuffer, dwSize * 2, NULL);
                    if (status)
                    {
                        VirtualFree(pbuffer, 0, MEM_RELEASE);
                        return ret;
                    }
                }
            }
            else
            {
                VirtualFree(pbuffer, 0, MEM_RELEASE);
                return ret;
            }
        }
    }

    if (!pbuffer || status)
        return ret;

    PSYSTEM_HANDLE_INFORMATION1 pHandleInfo = (PSYSTEM_HANDLE_INFORMATION1)pbuffer;

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++)
    {
        if (IsTargetPid(pHandleInfo->Handles[i].UniqueProcessId, Pids, WeCharProcCnt))
        {
            HANDLE hHandle = DuplicateHandleEx (
                pHandleInfo->Handles[i].UniqueProcessId,
                (HANDLE)pHandleInfo->Handles[i].HandleValue,
                DUPLICATE_SAME_ACCESS);

            if (hHandle)
            {
                DWORD dwFlags = 0;
                char buf[1024];
                status = NtQueryObject(hHandle, ObjectTypeInformation, buf, sizeof(buf), &dwFlags);
                if (!(status))
                {
                    POBJECT_NAME_INFORMATION pNameType = (POBJECT_NAME_INFORMATION)buf;

                    if ( (pNameType->Name.Length == sizeof(L"Mutant") - 2) &&
                         !memcmp(pNameType->Name.Buffer, L"Mutant", sizeof(L"Mutant") - 2) )
                    {
                        status = NtQueryObject(hHandle, ObjectNameInformation, buf, sizeof(buf), &dwFlags);
                        if (!(status))
                        {
                            POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)buf;
                            if (pNameType->Name.Length)
                            {
                                pNameType->Name.Buffer[pNameType->Name.Length/2] = 0;

                                //WeChat_aj5r8jpxt_Instance_Identity_Mutex_Name
                                //if (wcsstr(Name, L"_WeChat_App_Instance_Identity_Mutex_Name"))
                                if (wcsstr((PWCHAR)pNameType->Name.Buffer, L"_WeChat_") &&
                                    wcsstr((PWCHAR)pNameType->Name.Buffer, L"_Instance_Identity_Mutex_Name"))
                                {
                                    printf("%ws\n", pNameType->Name.Buffer);
                                    CloseHandle(hHandle);

                                    hHandle = DuplicateHandleEx (
                                        pHandleInfo->Handles[i].UniqueProcessId,
                                        (HANDLE)pHandleInfo->Handles[i].HandleValue,
                                        DUPLICATE_CLOSE_SOURCE);
                                }
                            }
                        }
                    }
                }

                CloseHandle(hHandle);
            }
        }
    }

    VirtualFree(pbuffer, 0, MEM_RELEASE);
    return ret;
}

VOID OpenNewWeChat()
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
            wcscat_s(wchFileName, L"\\WeChat.exe");
            printf("%ws\n", wchFileName);

            STARTUPINFO si = { sizeof(si) };
            PROCESS_INFORMATION pi = { 0 };

            if (CreateProcessW(NULL, wchFileName, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }

        CloseHandle(hKey);
    }
}

int main()
{
    ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQuerySystemInformation");

    NtQueryObject = (NTQUERYOBJECT)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

    PatchWeChat();
    OpenNewWeChat();

    getchar();
    return 0;
}