#include "ProcArmor.inl"

_Success_(return != NULL)
PPA_INIT
PA_Config_LoadFromExeExport(VOID)
{
    PVOID ExeBase = CONTAINING_RECORD(NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink,
                                      LDR_DATA_TABLE_ENTRY,
                                      InLoadOrderLinks)->DllBase;
    PIMAGE_NT_HEADERS NtHeader = Add2Ptr(ExeBase, ((PIMAGE_DOS_HEADER)ExeBase)->e_lfanew);
    if (NtHeader->OptionalHeader.NumberOfRvaAndSizes == 0)
    {
        return NULL;
    }
    PIMAGE_DATA_DIRECTORY ExportDir = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (ExportDir->VirtualAddress == 0 || ExportDir->Size == 0)
    {
        return NULL;
    }
    PIMAGE_EXPORT_DIRECTORY ExportTable = Add2Ptr(ExeBase, ExportDir->VirtualAddress);
    PDWORD pdw, NameRVAs = Add2Ptr(ExeBase, ExportTable->AddressOfNames);
    for (ULONG Index = 0; Index < ExportTable->NumberOfNames; Index++, NameRVAs++)
    {
        pdw = Add2Ptr(ExeBase, *NameRVAs);
        if (Add2Ptr(pdw, sizeof(ULONGLONG)) <= Add2Ptr(ExportTable, ExportDir->Size) &&
            /* PA_Init */
            pdw[0] == ('I_AP') && pdw[1] == ('tin'))
        {
            pdw = Add2Ptr(ExeBase, ExportTable->AddressOfFunctions);
            return Add2Ptr(ExeBase, pdw[((PWORD)(Add2Ptr(ExeBase, ExportTable->AddressOfNameOrdinals)))[Index]]);
        }
    }
    return NULL;
}
