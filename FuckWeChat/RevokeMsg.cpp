
#include "common.h"

WX_VERSION g_WX_Version[] = {
    { 2,6,5,38, 0x247EF1, 3, {0x8A, 0x45, 0xF3}, 3, {0x33, 0xc0, 0x90}},  // 33 C0   xor eax,eax
    { 2,6,6,25, 0x24BA81, 3, {0x8A, 0x45, 0xF3}, 3, {0x33, 0xc0, 0x90}},
    { 2,6,6,28, 0x24B451, 3, {0x8A, 0x45, 0xF3}, 3, {0x33, 0xc0, 0x90}},
    { 2,6,6,44, 0x24B821, 3, {0x8A, 0x45, 0xF3}, 3, {0x33, 0xc0, 0x90}},
    { 2,6,7,32, 0x252DB1, 3, {0x8A, 0x45, 0xF3}, 3, {0x33, 0xc0, 0x90}},
    { 2,6,7,40, 0x252E31, 3, {0x8A, 0x45, 0xF3}, 3, {0x33, 0xc0, 0x90}},
    { 2,6,7,57, 0x252C60, 3, {0x55, 0x8B, 0xEC}, 3, {0x33, 0xc0, 0xc3}},  // 33 C0   xor eax,eax  C3  ret
};

/* 2.6.5.38
text:10247EF1 8A 45 F3            mov     al, [ebp+var_D]
*/

void PatchRevokeMsg()
{
	ULONG offset;
	BYTE code[3];   
	WORD code_count;

	if (IsSupportedWxVersion(
            &g_WX_Version[0],
            sizeof(g_WX_Version)/sizeof(WX_VERSION),
            &offset,
            NULL,
            NULL,
            &code[0],
            &code_count))
    {
        HMODULE hMod = GetModuleHandleW(L_WECHATWINDLL);
        if (hMod)
        {
            PVOID addr = (BYTE*)hMod + offset;
            Patch(addr, code_count, code);
        }
	}
}

void RestoreRevokeMsg()
{
	DWORD offset = 0x247EF1;
	BYTE code[] = { 0x8A, 0x45, 0xF3 };
	WORD code_count = 3;

	if (IsSupportedWxVersion(
            &g_WX_Version[0],
            sizeof(g_WX_Version)/sizeof(WX_VERSION),
            &offset,
            &code[0],
            &code_count,
            NULL,
            NULL))
    {
        HMODULE hMod = GetModuleHandleW(L_WECHATWINDLL);
        if (hMod)
        {
            PVOID addr = (BYTE*)hMod + offset;
            Patch(addr, code_count, code);
        }
	}	
}
