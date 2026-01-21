#include "UnitTest.h"

static CONST UNICODE_STRING g_usMsidle = RTL_CONSTANT_STRING(L"msidle.dll");

TEST_FUNC(DllAttach)
{
    NTSTATUS Status;
    HANDLE ThreadHandle;
    THREAD_BASIC_INFORMATION tbi;
    PVOID DllBase;

    Status = RtlCreateUserThread(NtCurrentProcess(),
                                 NULL,
                                 FALSE,
                                 0,
                                 0,
                                 0,
                                 (PUSER_THREAD_START_ROUTINE)&LoadLibraryW,
                                 g_usMsidle.Buffer,
                                 &ThreadHandle,
                                 NULL);
    if (NT_SUCCESS(Status))
    {
        Status = NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
        if (Status == STATUS_WAIT_0)
        {
            Status = NtQueryInformationThread(ThreadHandle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
            if (NT_SUCCESS(Status))
            {
                TEST_OK(tbi.ExitStatus == STATUS_UNSUCCESSFUL);
                TEST_OK(LdrGetDllHandle(NULL, NULL, (PUNICODE_STRING)&g_usMsidle, &DllBase) == STATUS_DLL_NOT_FOUND);
            } else
            {
                TEST_SKIP("NtQueryInformationThread failed with 0x%08lX\n", Status);
            }
        } else
        {
            TEST_SKIP("NtWaitForSingleObject failed with 0x%08lX\n", Status);
        }
        NtClose(ThreadHandle);
    } else
    {
        TEST_SKIP("RtlCreateUserThread failed with 0x%08lX\n", Status);
    }

    return;
}
