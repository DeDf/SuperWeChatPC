
#pragma once

#include <stdio.h>
#include <windows.h>
#include <Shlwapi.h>

#define  L_WECHATWINDLL  L"WeChatWin.dll"

typedef struct _WX_VERSION {
    WORD major;
    WORD minor;
    WORD build;
    WORD rever;
    ULONG offset;
    WORD OrgCodeLen;
    UCHAR OrgCode[3];
    WORD PatchCodeLen;
    UCHAR PatchCode[3];
} WX_VERSION, *P_WX_VERSION;

bool
IsSupportedWxVersion (
                      P_WX_VERSION pWXVer,
                      INT ver_count,
                      ULONG* pOffset,
                      BYTE* orig_code,
                      WORD* orig_code_count,
                      BYTE* fake_code,
                      WORD* fake_code_count
                      );

void Patch(PVOID addr, DWORD size, PVOID code);




void PatchRevokeMsg();
