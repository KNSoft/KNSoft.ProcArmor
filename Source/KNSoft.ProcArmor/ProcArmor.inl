#pragma once

#include <KNSoft/NDK/NDK.h>
#include <KNSoft/SlimDetours/SlimDetours.h>
#include <KNSoft/MakeLifeEasier/MakeLifeEasier.h>

#pragma comment(lib, "../Release/KNSoft.SlimDetours.lib") // Release build for less imports
#pragma comment(lib, "KNSoft.MakeLifeEasier.lib")
#pragma comment(lib, "KNSoft.NDK.Ntdll.CRT.lib")

#include "ProcArmor.h"

typedef
_Function_class_(PA_VOID_FN)
VOID
PA_VOID_FN(VOID);
typedef PA_VOID_FN* PPA_VOID_FN;

typedef
_Function_class_(PA_SYSTEM_DLL_LOAD_CALLBACK)
VOID
PA_SYSTEM_DLL_LOAD_CALLBACK(
    _In_ PVOID* SystemDllBase);
typedef PA_SYSTEM_DLL_LOAD_CALLBACK* PPA_SYSTEM_DLL_LOAD_CALLBACK;

typedef
_Function_class_(PA_THREAD_START_CALLBACK)
__callback
NTSTATUS
PA_THREAD_START_CALLBACK(
    _In_ PVOID StartAddress);
typedef PA_THREAD_START_CALLBACK* PPA_THREAD_START_CALLBACK;

typedef
_Function_class_(PA_PAGE_PROTECT_CHANGE_CALLBACK)
__callback
NTSTATUS
PA_PAGE_PROTECT_CHANGE_CALLBACK(
    _In_ ULONG NewProtection,
    _In_opt_ PMEMORY_BASIC_INFORMATION MemInfo,
    _In_opt_ PVOID CallerBase);
typedef PA_PAGE_PROTECT_CHANGE_CALLBACK* PPA_PAGE_PROTECT_CHANGE_CALLBACK;

typedef struct _PA_UTIL_HOOK_FUNC
{
    CONST PVOID* DllBase;
    CONST ANSI_STRING Name;
    DECLSPEC_ALIGN(4) _Interlocked_operand_ long volatile RefCount;
    PVOID OriginalAddress;
    PVOID Address;
} PA_UTIL_HOOK_FUNC, *PPA_UTIL_HOOK_FUNC;

EXTERN_C DECLSPEC_POINTERALIGN _Interlocked_operand_ PPA_INIT volatile g_Init;
EXTERN_C PVOID g_hDll;
EXTERN_C PVOID g_hNtdll;
EXTERN_C PVOID g_hKernel32;
EXTERN_C PVOID g_hKernelBase;
EXTERN_C PVOID g_hUser32;

DECLSPEC_NORETURN
FORCEINLINE
VOID
__cdecl
PA_RaiseError(
    _In_ _Printf_format_string_ PCSTR Format,
    ...)
{
    UNREFERENCED_PARAMETER(Format);

    RtlFailFast(FAST_FAIL_FATAL_APP_EXIT);
}

NTSTATUS
PA_Event_NewThreadStart(
    _In_ PVOID StartAddress);

NTSTATUS
PA_Event_PageProtect(
    _In_ PVOID BaseAddress,
    _In_ SIZE_T RegionSize,
    _In_ LOGICAL IsNewAllocation,
    _In_ ULONG NewProtection,
    _In_ PVOID CallerBase);

/* Util.c */

NTSTATUS
PA_Util_GetSysDllBase(
    _In_ PCUNICODE_STRING DllName,
    _Out_ PVOID* DllHandle);

NTSTATUS
PA_Util_GetNtdllBase(
    _Out_ PVOID* NtdllBase);

NTSTATUS
PA_Util_SetHook(
    _In_ PPA_UTIL_HOOK_FUNC HookFunc,
    _In_ PVOID DetourFunc);

NTSTATUS
PA_Util_WriteCode(
    _In_ PVOID Address,
    _In_reads_bytes_(Length) CONST BYTE* OpCode,
    _In_ ULONG Length);

LOGICAL
PA_Util_IsExecutablePageProtect(
    _In_ ULONG Protect);

LOGICAL
PA_Util_IsWritablePageProtect(
    _In_ ULONG Protect);

BOOLEAN
PA_Util_IsCurrentProcess(
    _In_ HANDLE ProcessHandle);

/* Config.c */

_Success_(return != NULL)
PPA_INIT
PA_Config_LoadFromExeExport(VOID);

/* Hook.c */

VOID
PA_Hook_RtlUserThreadStart(VOID);

VOID
PA_Hook_NtProtectVirtualMemory(VOID);

VOID
PA_Hook_NtAllocateVirtualMemory(VOID);
