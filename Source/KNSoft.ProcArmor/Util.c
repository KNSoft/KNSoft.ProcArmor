#include "ProcArmor.inl"

static CONST UNICODE_STRING g_usNtdll = RTL_CONSTANT_STRING(L"ntdll.dll");

NTSTATUS
PA_Util_GetSysDllBase(
    _In_ PCUNICODE_STRING DllName,
    _Out_ PVOID* DllHandle)
{
    return LdrGetDllHandleEx(LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT,
                             NULL,
                             NULL,
                             (PUNICODE_STRING)DllName,
                             DllHandle);
}

NTSTATUS
PA_Util_GetNtdllBase(
    _Out_ PVOID* NtdllBase)
{
    /* Get the first initialized entry */
    PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(NtCurrentPeb()->Ldr->InInitializationOrderModuleList.Flink,
                                                    LDR_DATA_TABLE_ENTRY,
                                                    InInitializationOrderLinks);

    /* May be replaced by honey pot by very few tamper security softwares */
    if (RtlEqualUnicodeString(&Entry->BaseDllName, (PUNICODE_STRING)&g_usNtdll, TRUE))
    {
        *NtdllBase = Entry->DllBase;
        return STATUS_SUCCESS;
    }

    /* Fallback to LdrGetDllHandleEx */
    return PA_Util_GetSysDllBase(&g_usNtdll, NtdllBase);
}

NTSTATUS
PA_Util_SetHook(
    _In_ PPA_UTIL_HOOK_FUNC HookFunc,
    _In_ PVOID DetourFunc)
{
    if (_InterlockedIncrement(&HookFunc->RefCount) != 0)
    {
        return S_OK;
    }

    NTSTATUS Status;
    PVOID pfn;

    Status = PS_GetProcAddress(*HookFunc->DllBase, (PCANSI_STRING)&HookFunc->Name, &pfn);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    HookFunc->OriginalAddress = HookFunc->Address = pfn;
    return SlimDetoursInlineHook(TRUE, &HookFunc->Address, DetourFunc) & ~FACILITY_NT_BIT;
}

/* TODO: Mem_WriteCode */
NTSTATUS
PA_Util_WriteCode(
    _In_ PVOID Address,
    _In_reads_bytes_(Length) CONST BYTE* OpCode,
    _In_ ULONG Length)
{
    NTSTATUS Status;
    ULONG OldProtect;

    Status = Mem_ProtectPage(Address, Length, PAGE_EXECUTE_READWRITE, &OldProtect);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    memcpy(Address, OpCode, Length);
    Mem_ProtectPage(Address, Length, OldProtect, &OldProtect);
    NtFlushInstructionCache(NtCurrentProcess(), Address, Length);
    return STATUS_SUCCESS;
}

BOOLEAN
PA_Util_IsCurrentProcess(
    _In_ HANDLE ProcessHandle)
{
    if (ProcessHandle == NtCurrentProcess())
    {
        return TRUE;
    }

    PROCESS_BASIC_INFORMATION pbi;
    if (NT_SUCCESS(NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)) &&
        pbi.UniqueProcessId == NtCurrentProcessId())
    {
        return TRUE;
    }

    return FALSE;
}

LOGICAL
PA_Util_IsExecutablePageProtect(
    _In_ ULONG Protect)
{
    return Protect == PAGE_EXECUTE ||
        Protect == PAGE_EXECUTE_READ ||
        Protect == PAGE_EXECUTE_READWRITE ||
        Protect == PAGE_EXECUTE_WRITECOPY;
}

LOGICAL
PA_Util_IsWritablePageProtect(
    _In_ ULONG Protect)
{
    return Protect == PAGE_READWRITE ||
        Protect == PAGE_WRITECOPY ||
        Protect == PAGE_EXECUTE_READWRITE ||
        Protect == PAGE_EXECUTE_WRITECOPY;
}
