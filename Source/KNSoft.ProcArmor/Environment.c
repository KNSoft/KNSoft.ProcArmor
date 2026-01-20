#include "ProcArmor.inl"

_Function_class_(PA_VOID_FN)
VOID
PA_Environment_Init(VOID)
{
    if (g_Init->Environment.KDDetect)
    {
        if (SharedUserData->KdDebuggerEnabled)
        {
            PA_RaiseError("KD Debugger Enabled!\n");
        }
    }
    if (g_Init->Environment.TestingModeDetect)
    {
        NTSTATUS Status;
        SYSTEM_CODEINTEGRITY_INFORMATION sci;

        sci.Length = sizeof(sci);
        Status = NtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), NULL);
        if (NT_SUCCESS(Status) && sci.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN)
        {
            PA_RaiseError("Test Mode Enabled!\n");
        }
    }
}
