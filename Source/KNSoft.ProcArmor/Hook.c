#include "ProcArmor.inl"

#pragma region RtlUserThreadStart

static PA_UTIL_HOOK_FUNC g_hfRtlUserThreadStart = { &g_hNtdll, RTL_CONSTANT_STRING("RtlUserThreadStart"), 0, NULL, NULL };
CONST PVOID* g_ppfnRtlUserThreadStart = &g_hfRtlUserThreadStart.Address;

#if defined(_M_IX86)

EXTERN_C
VOID
NTAPI
Hooked_RtlUserThreadStart(
    _In_ PUSER_THREAD_START_ROUTINE Function,
    _In_ PVOID Parameter);

#else

static
VOID
NTAPI
Hooked_RtlUserThreadStart(
    _In_ PUSER_THREAD_START_ROUTINE Function,
    _In_ PVOID Parameter)
{
    NTSTATUS Status = PA_Event_NewThreadStart(Function);
    if (NT_SUCCESS(Status))
    {
        ((typeof(&RtlUserThreadStart))g_hfRtlUserThreadStart.Address)(Function, Parameter);
    }
    RtlExitUserThread(Status);
    RtlFailFast(FAST_FAIL_INVALID_THREAD_STATE);
}

#endif

VOID
PA_Hook_RtlUserThreadStart(VOID)
{
    HRESULT hr = PA_Util_SetHook(&g_hfRtlUserThreadStart, (PVOID)&Hooked_RtlUserThreadStart);
    if (FAILED(hr))
    {
        PA_RaiseError("Hook RtlUserThreadStart failed with 0x%08lX\n", hr);
    }
}

#pragma endregion RtlUserThreadStart

#pragma region NtProtectVirtualMemory

static PA_UTIL_HOOK_FUNC g_hfNtProtectVirtualMemory = { &g_hNtdll, RTL_CONSTANT_STRING("NtProtectVirtualMemory"), 0, NULL, NULL };

static
NTSTATUS
NTAPI
Hooked_NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection)
{
    if (!PA_Util_IsCurrentProcess(ProcessHandle))
    {
        goto _Pass;
    }
    PVOID CallerBase;
    CallerBase = RtlPcToFileHeader(_ReturnAddress(), &CallerBase);
    if (CallerBase == g_hNtdll)
    {
        goto _Pass;
    }

    NTSTATUS Status = PA_Event_PageProtect(*BaseAddress, *RegionSize, FALSE, NewProtection, CallerBase);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

_Pass:
    return ((typeof(&NtProtectVirtualMemory))g_hfNtProtectVirtualMemory.Address)(ProcessHandle,
                                                                                 BaseAddress,
                                                                                 RegionSize,
                                                                                 NewProtection,
                                                                                 OldProtection);
}

VOID
PA_Hook_NtProtectVirtualMemory(VOID)
{
    NTSTATUS Status;

    Status = PA_Util_SetHook(&g_hfNtProtectVirtualMemory, (PVOID)&Hooked_NtProtectVirtualMemory);
    if (!NT_SUCCESS(Status))
    {
        PA_RaiseError("Hook NtProtectVirtualMemory failed with 0x%08lX\n", Status);
    }
}

#pragma endregion NtProtectVirtualMemory

#pragma region NtAllocateVirtualMemory[Ex]

static PA_UTIL_HOOK_FUNC g_hfNtAllocateVirtualMemory = { &g_hNtdll, RTL_CONSTANT_STRING("NtAllocateVirtualMemory"), 0, NULL, NULL };
static PA_UTIL_HOOK_FUNC g_hfNtAllocateVirtualMemoryEx = { &g_hNtdll, RTL_CONSTANT_STRING("NtAllocateVirtualMemoryEx"), 0, NULL, NULL };

static
NTSTATUS
ProcessNtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _In_ PVOID ReturnAddress)
{
    if (!PA_Util_IsCurrentProcess(ProcessHandle) || !FlagOn(AllocationType, MEM_COMMIT))
    {
        return STATUS_SUCCESS;
    }
    PVOID CallerBase;
    CallerBase = RtlPcToFileHeader(ReturnAddress, &CallerBase);

    return PA_Event_PageProtect(BaseAddress, RegionSize, TRUE, PageProtection, CallerBase);
}

static
_Must_inspect_result_
_When_(return == 0, __drv_allocatesMem(mem))
NTSTATUS
NTAPI
Hooked_NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID * BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection)
{
    NTSTATUS Status = ProcessNtAllocateVirtualMemory(ProcessHandle,
                                                     *BaseAddress,
                                                     *RegionSize,
                                                     AllocationType,
                                                     PageProtection,
                                                     _ReturnAddress());
    if (NT_SUCCESS(Status))
    {
        Status = ((typeof(&NtAllocateVirtualMemory))g_hfNtAllocateVirtualMemory.Address)(ProcessHandle,
                                                                                         BaseAddress,
                                                                                         ZeroBits,
                                                                                         RegionSize,
                                                                                         AllocationType,
                                                                                         PageProtection);
    }
    return Status;
}

static
_Must_inspect_result_
_When_(return == 0, __drv_allocatesMem(Mem))
NTSTATUS
NTAPI
Hooked_NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID * BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount)
{
    NTSTATUS Status = ProcessNtAllocateVirtualMemory(ProcessHandle,
                                                     *BaseAddress,
                                                     *RegionSize,
                                                     AllocationType,
                                                     PageProtection,
                                                     _ReturnAddress());
    if (NT_SUCCESS(Status))
    {
        Status = ((typeof(&NtAllocateVirtualMemoryEx))g_hfNtAllocateVirtualMemoryEx.Address)(ProcessHandle,
                                                                                             BaseAddress,
                                                                                             RegionSize,
                                                                                             AllocationType,
                                                                                             PageProtection,
                                                                                             ExtendedParameters,
                                                                                             ExtendedParameterCount);
    }
    return Status;
}

VOID
PA_Hook_NtAllocateVirtualMemory(VOID)
{
    NTSTATUS Status;

    Status = PA_Util_SetHook(&g_hfNtAllocateVirtualMemory, (PVOID)&Hooked_NtAllocateVirtualMemory);
    if (!NT_SUCCESS(Status))
    {
        PA_RaiseError("Hook NtAllocateVirtualMemory failed with 0x%08lX\n", Status);
    }
    PA_Util_SetHook(&g_hfNtAllocateVirtualMemoryEx, (PVOID)&Hooked_NtAllocateVirtualMemoryEx);
}

#pragma endregion NtAllocateVirtualMemory
