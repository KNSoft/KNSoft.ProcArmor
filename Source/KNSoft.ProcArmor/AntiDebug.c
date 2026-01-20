#include "ProcArmor.inl"

static CONST BYTE g_abFastFail[] = {
#if defined(_M_IX86) || (defined(_M_X64) && !defined(_M_ARM64EC))
    0x29
#elif defined (_M_ARM64) || defined(_M_ARM64EC)
    0xF0, 0x03
#else
#error
#endif
};

static CONST ANSI_STRING g_asBreakPointFunc[] = {
    RTL_CONSTANT_STRING("DbgUiRemoteBreakin"),
    RTL_CONSTANT_STRING("DbgBreakPoint"),
    RTL_CONSTANT_STRING("DbgUserBreakPoint")
};

static PVOID g_pfnBreakPointFunc[ARRAYSIZE(g_asBreakPointFunc)] = { 0 };

static PVOID g_pfnDbgUiRemoteBreakin = NULL;

static
VOID
NTAPI
Hooked_DbgUiRemoteBreakin(
    _In_ PVOID Context)
{
    RtlExitUserThread(STATUS_DEBUG_ATTACH_FAILED);
    RtlFailFast(FAST_FAIL_INVALID_THREAD_STATE);
}

FORCEINLINE
NTSTATUS
PA_AntiDebug_HideThreadFromDebugger(
    _In_ HANDLE ThreadHandle)
{
    return NtSetInformationThread(ThreadHandle, ThreadHideFromDebugger, NULL, 0);
}

_Function_class_(PA_VOID_FN)
VOID
PA_AntiDebug_Init(VOID)
{
    if (!g_Init->AntiDebug.Enable)
    {
        return;
    }

    NTSTATUS Status;
    HANDLE PrevThreadHandle, ThreadHandle;

    /* Break debug breaks */
    for (ULONG i = 0; i < ARRAYSIZE(g_asBreakPointFunc); i++)
    {
        Status = PS_GetProcAddress(g_hNtdll, (PCANSI_STRING)&g_asBreakPointFunc[i], &g_pfnBreakPointFunc[i]);
        if (NT_SUCCESS(Status) && i > 0)
        {
            PA_Util_WriteCode(g_pfnBreakPointFunc[i], g_abFastFail, sizeof(g_abFastFail));
        }
    }
    if (g_pfnBreakPointFunc[0] != NULL)
    {
        g_pfnDbgUiRemoteBreakin = g_pfnBreakPointFunc[0];
        SlimDetoursInlineHook(TRUE, &g_pfnDbgUiRemoteBreakin, (PVOID)&Hooked_DbgUiRemoteBreakin);
    }

    /* Hook RtlUserThreadStart */
    PA_Hook_RtlUserThreadStart();

    /* Hide threads from debugger */
    PrevThreadHandle = NULL;
_Next_Thread:
    Status = NtGetNextThread(NtCurrentProcess(),
                             PrevThreadHandle,
                             THREAD_SET_INFORMATION,
                             0,
                             0,
                             &ThreadHandle);
    if (PrevThreadHandle != NULL)
    {
        NtClose(PrevThreadHandle);
    }
    if (NT_SUCCESS(Status))
    {
        /* False positive, *ThreadHandle is outputed by a success NtGetNextThread call */
#pragma warning(disable: __WARNING_USING_UNINIT_VAR)
        PA_AntiDebug_HideThreadFromDebugger(ThreadHandle);
#pragma warning(default: __WARNING_USING_UNINIT_VAR)
        PrevThreadHandle = ThreadHandle;
        goto _Next_Thread;
    }
}

static
LOGICAL
CheckContextDr(
    _In_ PCONTEXT ctx)
{
    PDWORD pdw;
    ULONG cdw;

#if defined(_M_IX86) || (defined(_M_X64) && !defined(_M_ARM64EC))
    pdw = (PDWORD)&ctx->Dr0;
    cdw = sizeof(SIZE_T) / sizeof(DWORD) * 6;
#elif defined(_M_ARM64) || !defined(_M_ARM64EC)
    pdw = ctx->Bcr;
    cdw = (ARM64_MAX_BREAKPOINTS + ARM64_MAX_WATCHPOINTS) * 3;
#else
#error
#endif
    do
    {
        if (*pdw++ != 0)
        {
            return FALSE;
        }
    } while (--cdw != 0);
    return TRUE;
}

_Function_class_(PA_THREAD_START_CALLBACK)
__callback
NTSTATUS
PA_AntiDebug_NewThreadStart(
    _In_ PVOID StartAddress)
{
    if (!g_Init->AntiDebug.Enable)
    {
        return STATUS_SUCCESS;
    }
    
    PA_AntiDebug_HideThreadFromDebugger(NtCurrentThread());
    for (ULONG i = 0; i < ARRAYSIZE(g_pfnBreakPointFunc); i++)
    {
        if (g_pfnBreakPointFunc[i] != NULL && StartAddress == g_pfnBreakPointFunc[i])
        {
            return STATUS_DEBUG_ATTACH_FAILED;
        }
    }

    return STATUS_SUCCESS;
}

_Function_class_(PA_VOID_FN)
VOID
PA_AntiDebug_RTP(VOID)
{
    if (!g_Init->AntiDebug.Enable)
    {
        return;
    }

    NTSTATUS Status;
    HANDLE PrevThreadHandle, ThreadHandle;
    BOOLEAN b;
    CONTEXT ctx;

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    /* Check debug flags */
    if (NtCurrentPeb()->BeingDebugged)
    {
        PA_RaiseError("PEB::BeingDebugged is set\n");
    }

    /* Check all threads' state */
    PrevThreadHandle = NULL;
_Next_Thread:
    Status = NtGetNextThread(NtCurrentProcess(),
                             PrevThreadHandle,
                             THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION | THREAD_GET_CONTEXT,
                             0,
                             0,
                             &ThreadHandle);
    if (PrevThreadHandle != NULL)
    {
        NtClose(PrevThreadHandle);
    }
    if (NT_SUCCESS(Status))
    {
        /* False positive, *ThreadHandle is outputed by a success NtGetNextThread call */
#pragma warning(disable: __WARNING_USING_UNINIT_VAR)
        Status = NtQueryInformationThread(ThreadHandle, ThreadHideFromDebugger, &b, sizeof(b), NULL);
        if (!NT_SUCCESS(Status) || !b)
        {
            PA_AntiDebug_HideThreadFromDebugger(ThreadHandle);
        }
        Status = NtGetContextThread(ThreadHandle, &ctx);
        if (NT_SUCCESS(Status))
        {
            if (!CheckContextDr(&ctx))
            {
                PA_RaiseError("DR is set\n");
            }
        }
#pragma warning(default: __WARNING_USING_UNINIT_VAR)
        PrevThreadHandle = ThreadHandle;
        goto _Next_Thread;
    }
}
