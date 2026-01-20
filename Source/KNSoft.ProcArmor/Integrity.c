#include "ProcArmor.inl"

_Function_class_(PA_VOID_FN)
VOID
PA_Integrity_Init(VOID)
{
    if (g_Init->Integrity.BlockDynamicCode)
    {
        PA_Hook_RtlUserThreadStart();
        PA_Hook_NtProtectVirtualMemory();
        PA_Hook_NtAllocateVirtualMemory();
    }
}

_Function_class_(PA_THREAD_START_CALLBACK)
__callback
NTSTATUS
PA_Integrity_NewThreadStart(
    _In_ PVOID StartAddress)
{
    if (g_Init->Integrity.BlockDynamicCode)
    {
        PVOID CodeBase;
        if (RtlPcToFileHeader(StartAddress, &CodeBase) == NULL)
        {
            return STATUS_DYNAMIC_CODE_BLOCKED;
        }
        MEMORY_BASIC_INFORMATION mbi;
        if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
                                             StartAddress,
                                             MemoryBasicInformation,
                                             &mbi,
                                             sizeof(mbi),
                                             NULL)) ||
            mbi.Type != MEM_IMAGE ||
            PA_Util_IsWritablePageProtect(mbi.Protect))
        {
            return STATUS_DYNAMIC_CODE_BLOCKED;
        }
    }

    return STATUS_SUCCESS;
}

_Function_class_(PA_PAGE_PROTECT_CHANGE_CALLBACK)
__callback
NTSTATUS
PA_Integrity_PageProtectChange(
    _In_ ULONG NewProtection,
    _In_opt_ PMEMORY_BASIC_INFORMATION MemInfo,
    _In_opt_ PVOID CallerBase)
{
    if (g_Init->Integrity.BlockDynamicCode)
    {
        if (CallerBase == NULL)
        {
            return STATUS_DYNAMIC_CODE_BLOCKED;
        }
        if (MemInfo != NULL)
        {
            /* A non-executable memory region become executable */
            if (!PA_Util_IsExecutablePageProtect(MemInfo->Protect) && PA_Util_IsExecutablePageProtect(NewProtection))
            {
                return STATUS_DYNAMIC_CODE_BLOCKED;
            }
            /* A read-only executable memory region become writable */
            if (PA_Util_IsExecutablePageProtect(MemInfo->Protect) &&
                !PA_Util_IsWritablePageProtect(MemInfo->Protect) &&
                PA_Util_IsWritablePageProtect(NewProtection) &&
                CallerBase != g_hDll)
            {
                return STATUS_DYNAMIC_CODE_BLOCKED;
            }
        } else
        {
            /* New allocating a memory region that executable and writable */
            if (NewProtection == PAGE_EXECUTE_READWRITE || NewProtection == PAGE_EXECUTE_WRITECOPY)
            {
                return STATUS_DYNAMIC_CODE_BLOCKED;
            }
        }
    }
    return STATUS_SUCCESS;
}
