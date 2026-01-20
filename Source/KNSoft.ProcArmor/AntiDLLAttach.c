#include "ProcArmor.inl"

static PA_UTIL_HOOK_FUNC g_hfLoadDll[] = {
    { &g_hNtdll, RTL_CONSTANT_STRING("LdrLoadDll"), 0, NULL, NULL },
    { &g_hKernel32, RTL_CONSTANT_STRING("LoadLibraryW"), 0, NULL, NULL },
    { &g_hKernel32, RTL_CONSTANT_STRING("LoadLibraryA"), 0, NULL, NULL },
    { &g_hKernel32, RTL_CONSTANT_STRING("LoadLibraryExW"), 0, NULL, NULL },
    { &g_hKernel32, RTL_CONSTANT_STRING("LoadLibraryExA"), 0, NULL, NULL },
};

static
LOGICAL
AllowDllLoad(
    _In_ PVOID ReturnAddress)
{
    PVOID CallerBase;
    
    CallerBase = RtlPcToFileHeader(ReturnAddress, &CallerBase);
    if (g_Init->AntiDLLAttach.AntiRemoteCall)
    {
        if (CallerBase == NULL || CallerBase == g_hNtdll)
        {
            return FALSE;
        }
    }
    if (g_Init->AntiDLLAttach.AntiWindowHook)
    {
        if (g_hUser32 != NULL && CallerBase == g_hUser32)
        {
            return FALSE;
        }
    }

    return TRUE;
}

static
NTSTATUS
NTAPI
Hooked_LdrLoadDll(
    _In_opt_ PCWSTR DllPath,
    _In_opt_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID* DllHandle)
{
    if (!AllowDllLoad(_ReturnAddress()))
    {
        return STATUS_ACCESS_DENIED;
    }
    return ((typeof(&LdrLoadDll))g_hfLoadDll[0].Address)(DllPath,
                                                         DllCharacteristics,
                                                         DllName,
                                                         DllHandle);
}

static
_Ret_maybenull_
HMODULE
WINAPI
Hooked_LoadLibraryW(
    _In_ LPCWSTR lpLibFileName)
{
    if (!AllowDllLoad(_ReturnAddress()))
    {
        _Inline_BaseSetLastNTError(STATUS_ACCESS_DENIED);
        return NULL;
    }
    return ((typeof(&LoadLibraryW))g_hfLoadDll[1].Address)(lpLibFileName);
}

static
_Ret_maybenull_
HMODULE
WINAPI
Hooked_LoadLibraryA(
    _In_ LPCSTR lpLibFileName)
{
    if (!AllowDllLoad(_ReturnAddress()))
    {
        _Inline_BaseSetLastNTError(STATUS_ACCESS_DENIED);
        return NULL;
    }
    return ((typeof(&LoadLibraryA))g_hfLoadDll[2].Address)(lpLibFileName);
}

static
_Ret_maybenull_
HMODULE
WINAPI
Hooked_LoadLibraryExW(
    _In_ LPCWSTR lpLibFileName,
    _Reserved_ HANDLE hFile,
    _In_ DWORD dwFlags)
{
    if (!AllowDllLoad(_ReturnAddress()))
    {
        _Inline_BaseSetLastNTError(STATUS_ACCESS_DENIED);
        return NULL;
    }
    return ((typeof(&LoadLibraryExW))g_hfLoadDll[3].Address)(lpLibFileName, hFile, dwFlags);
}

static
_Ret_maybenull_
HMODULE
WINAPI
Hooked_LoadLibraryExA(
    _In_ LPCSTR lpLibFileName,
    _Reserved_ HANDLE hFile,
    _In_ DWORD dwFlags)
{
    if (!AllowDllLoad(_ReturnAddress()))
    {
        _Inline_BaseSetLastNTError(STATUS_ACCESS_DENIED);
        return NULL;
    }
    return ((typeof(&LoadLibraryExA))g_hfLoadDll[4].Address)(lpLibFileName, hFile, dwFlags);
}

static CONST PVOID g_pfnHookedLoadDll[] = {
    (PVOID)&Hooked_LoadLibraryW,
    (PVOID)&Hooked_LoadLibraryA,
    (PVOID)&Hooked_LoadLibraryExW,
    (PVOID)&Hooked_LoadLibraryExA,
};

_Function_class_(PA_VOID_FN)
VOID
PA_AntiDLLAttach_Init(VOID)
{
    if (g_Init->AntiDLLAttach.AntiRemoteCall)
    {
        PA_Util_SetHook(&g_hfLoadDll[0], (PVOID)&Hooked_LdrLoadDll);
        PA_Hook_RtlUserThreadStart();
    }
}

_Function_class_(PA_THREAD_START_CALLBACK)
__callback
NTSTATUS
PA_AntiDLLAttach_NewThreadStart(
    _In_ PVOID StartAddress)
{
    if (!g_Init->AntiDLLAttach.AntiRemoteCall)
    {
        return STATUS_SUCCESS;
    }

    for (ULONG i = 0; i < ARRAYSIZE(g_hfLoadDll); i++)
    {
        if (g_hfLoadDll[i].OriginalAddress != NULL &&
            Math_AbsDiff((LONG_PTR)StartAddress, (LONG_PTR)g_hfLoadDll[i].OriginalAddress) <= 10)
        {
            return STATUS_UNSUCCESSFUL;
        }
    }

    return STATUS_SUCCESS;
}

_Function_class_(PA_SYSTEM_DLL_LOAD_CALLBACK)
VOID
PA_AntiDLLAttach_SysDllLoad(
    _In_ PVOID* SystemDllBase)
{
    if (SystemDllBase == &g_hKernel32)
    {
        for (ULONG i = 1; i < ARRAYSIZE(g_hfLoadDll); i++)
        {
            PA_Util_SetHook(&g_hfLoadDll[i], g_pfnHookedLoadDll[i - 1]);
        }
    }
}
