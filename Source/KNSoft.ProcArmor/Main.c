#include "ProcArmor.inl"

DECLSPEC_POINTERALIGN _Interlocked_operand_ PPA_INIT volatile g_Init = NULL;

/* System DLL loading */

PVOID g_hDll = NULL, g_hNtdll = NULL, g_hKernel32 = NULL, g_hKernelBase = NULL, g_hUser32 = NULL;
PVOID g_DllLoadCookie = NULL;

static CONST UNICODE_STRING g_usKernel32 = RTL_CONSTANT_STRING(L"kernel32.dll");
static CONST UNICODE_STRING g_usKernelBase = RTL_CONSTANT_STRING(L"KernelBase.dll");
static CONST UNICODE_STRING g_usUser32 = RTL_CONSTANT_STRING(L"user32.dll");

EXTERN_C PA_SYSTEM_DLL_LOAD_CALLBACK PA_AntiDLLAttach_SysDllLoad;

static CONST PPA_SYSTEM_DLL_LOAD_CALLBACK g_apfnDllLoadCallback[] = {
    &PA_AntiDLLAttach_SysDllLoad,
};

/* Initialization functions */

EXTERN_C PA_VOID_FN PA_AntiDebug_Init;
EXTERN_C PA_VOID_FN PA_AntiDLLAttach_Init;
EXTERN_C PA_VOID_FN PA_Integrity_Init;
EXTERN_C PA_VOID_FN PA_Environment_Init;

static CONST PPA_VOID_FN g_apfnInit[] = {
    &PA_AntiDebug_Init,
    &PA_AntiDLLAttach_Init,
    &PA_Integrity_Init,
    &PA_Environment_Init,
};

/* Event callbacks */

EXTERN_C PA_THREAD_START_CALLBACK PA_AntiDebug_NewThreadStart;
EXTERN_C PA_THREAD_START_CALLBACK PA_AntiDLLAttach_NewThreadStart;
EXTERN_C PA_THREAD_START_CALLBACK PA_Integrity_NewThreadStart;

static CONST PPA_THREAD_START_CALLBACK g_apfnThreadStartCallback[] = {
    &PA_AntiDebug_NewThreadStart,
    &PA_AntiDLLAttach_NewThreadStart,
    &PA_Integrity_NewThreadStart,
};

EXTERN_C PA_PAGE_PROTECT_CHANGE_CALLBACK PA_Integrity_PageProtectChange;

static CONST PPA_PAGE_PROTECT_CHANGE_CALLBACK g_apfnPageProtectChangeCallback[] = {
    &PA_Integrity_PageProtectChange,
};

/* RTP functions */

EXTERN_C PA_VOID_FN PA_AntiDebug_RTP;

static CONST PPA_VOID_FN g_apfnRTP[] = {
    &PA_AntiDebug_RTP,
};

static
_Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS
NTAPI
PA_RTPThread(
    _In_ PVOID ThreadParameter)
{
    ULONG i;

_RTP_Loop:
    for (i = 0; i < ARRAYSIZE(g_apfnRTP); i++)
    {
        g_apfnRTP[i]();
    }

    PS_DelayExec((16UL - g_Init->RuntimeCheck.Frequence) * 1000);
    YieldProcessor();
    goto _RTP_Loop;
}

static
VOID
CallDllLoadCallbacks(
    _In_ PVOID* SystemDllBase)
{
    for (ULONG i = 0; i < ARRAYSIZE(g_apfnDllLoadCallback); i++)
    {
        g_apfnDllLoadCallback[i](SystemDllBase);
    }
}

static
_Function_class_(LDR_DLL_NOTIFICATION_FUNCTION)
VOID
CALLBACK
DllLoadCallback(
    _In_ ULONG NotificationReason,
    _In_ PCLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID Context)
{
    if (NotificationReason != LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        return;
    }
    if (RtlEqualUnicodeString((PUNICODE_STRING)NotificationData->Loaded.BaseDllName,
                              (PUNICODE_STRING)&g_usKernel32,
                              TRUE))
    {
        g_hKernel32 = NotificationData->Loaded.DllBase;
        if (g_hUser32 != NULL)
        {
            LdrUnregisterDllNotification(g_DllLoadCookie);
        }
        PA_Util_GetSysDllBase(&g_usKernelBase, &g_hKernelBase);
        CallDllLoadCallbacks(&g_hKernel32);
    } else if (RtlEqualUnicodeString((PUNICODE_STRING)NotificationData->Loaded.BaseDllName,
                                     (PUNICODE_STRING)&g_usUser32,
                                     TRUE))
    {
        g_hUser32 = NotificationData->Loaded.DllBase;
        if (g_hKernel32 != NULL)
        {
            LdrUnregisterDllNotification(g_DllLoadCookie);
        }
        CallDllLoadCallbacks(&g_hUser32);
    }
}

VOID
APIENTRY
PA_Initialize(
    _In_ PPA_INIT Init)
{
    if (_InterlockedCompareExchangePointer(&g_Init, Init, NULL) != NULL)
    {
        return;
    }

    NTSTATUS Status;

    Status = PA_Util_GetNtdllBase(&g_hNtdll);
    if (!NT_SUCCESS(Status))
    {
        PA_RaiseError("GetNtdllBase failed with 0x%08lX\n", Status);
    }
    if (NT_SUCCESS(PA_Util_GetSysDllBase(&g_usKernel32, &g_hKernel32)))
    {
        PA_Util_GetSysDllBase(&g_usKernelBase, &g_hKernelBase);
        CallDllLoadCallbacks(&g_hKernel32);
    }
    if (NT_SUCCESS(PA_Util_GetSysDllBase(&g_usUser32, &g_hUser32)))
    {
        CallDllLoadCallbacks(&g_hUser32);
    }
    if (g_hKernel32 == NULL || g_hUser32 == NULL)
    {
        LdrRegisterDllNotification(0, DllLoadCallback, NULL, &g_DllLoadCookie);
    }

    for (ULONG i = 0; i < ARRAYSIZE(g_apfnInit); i++)
    {
        g_apfnInit[i]();
    }

    RtlCreateUserThread(NtCurrentProcess(),
                        NULL,
                        FALSE,
                        0,
                        0,
                        0,
                        PA_RTPThread,
                        NULL,
                        NULL,
                        NULL);
}

BOOL
WINAPI
_DllMainCRTStartup(
    _In_ HMODULE DllHandle,
    _In_ DWORD Reason,
    _In_opt_ LPVOID Reserved)
{
    if (Reason == DLL_PROCESS_ATTACH)
    {
        LdrDisableThreadCalloutsForDll(DllHandle);

        g_hDll = DllHandle;
        PPA_INIT pInit = PA_Config_LoadFromExeExport();
        if (pInit != NULL)
        {
            PA_Initialize(pInit);
        }
    } else if (Reason == DLL_PROCESS_DETACH)
    {
        if (Reserved == NULL)
        {
            PA_RaiseError("Unload by a call!");
        }
    }

    return TRUE;
}

/* Events */

NTSTATUS
PA_Event_NewThreadStart(
    _In_ PVOID StartAddress)
{
    NTSTATUS Status;

    for (ULONG i = 0; i < ARRAYSIZE(g_apfnThreadStartCallback); i++)
    {
        Status = g_apfnThreadStartCallback[i](StartAddress);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
PA_Event_PageProtect(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ LOGICAL IsNewAllocation,
    _In_ ULONG NewProtection,
    _In_ PVOID CallerBase)
{
    NTSTATUS Status;
    MEMORY_BASIC_INFORMATION mbi, *pmbi;

    if (!IsNewAllocation)
    {
        Status = NtQueryVirtualMemory(NtCurrentProcess(),
                                      BaseAddress,
                                      MemoryBasicInformation,
                                      &mbi,
                                      sizeof(mbi),
                                      NULL);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
        if (mbi.Protect == NewProtection)
        {
            return STATUS_SUCCESS;
        }
        pmbi = &mbi;
    } else
    {
        pmbi = NULL;
    }

    for (ULONG i = 0; i < ARRAYSIZE(g_apfnPageProtectChangeCallback); i++)
    {
        Status = g_apfnPageProtectChangeCallback[i](NewProtection, pmbi, CallerBase);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }

    return STATUS_SUCCESS;
}
