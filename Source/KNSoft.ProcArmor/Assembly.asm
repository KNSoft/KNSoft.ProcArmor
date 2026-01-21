IFDEF _M_IX86

.MODEL FLAT, STDCALL

INCLUDE KNSoft\NDK\Assembly\Header.inc
INCLUDE KNSoft\NDK\Assembly\NDK.inc

RtlExitUserThread PROTO STDCALL :SIZE_T

PA_Event_NewThreadStart PROTO C :SIZE_T ; NTSTATUS PA_Event_NewThreadStart(_In_ PVOID StartAddress)

EXTERN g_ppfnRtlUserThreadStart:SIZE_T ; CONST PVOID* g_ppfnRtlUserThreadStart

.CODE

; VOID NTAPI Hooked_RtlUserThreadStart(_In_ PUSER_THREAD_START_ROUTINE Function, _In_ PVOID Parameter)
; eax = (PTHREAD_START_ROUTINE)pfnStartAddr
; ebx = (PVOID)pvParam
$PUBLIC_LABEL Hooked_RtlUserThreadStart@8
    ALIGN 16
    push eax
    invoke PA_Event_NewThreadStart, eax
    test eax, eax
    js @F
    mov eax, g_ppfnRtlUserThreadStart
    mov eax, [eax]
    xchg eax, [esp]
    retn
@@:
    invoke RtlExitUserThread, eax
    ; __fastfail(FAST_FAIL_INVALID_THREAD_STATE), should not reach here
    mov ecx, 74
    int 29h

ENDIF ; _M_IX86

    END
