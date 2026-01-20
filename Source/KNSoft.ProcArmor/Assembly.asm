IFDEF _M_IX86

.MODEL FLAT, STDCALL

INCLUDE KNSoft\NDK\Assembly\Header.inc
INCLUDE KNSoft\NDK\Assembly\NDK.inc

RtlExitUserThread PROTO STDCALL :SIZE_T

PA_Event_NewThreadStart PROTO C :SIZE_T ; NTSTATUS NTAPI PA_Event_NewThreadStart(_In_ PVOID StartAddress)

EXTERN g_ppfnRtlUserThreadStart:SIZE_T ; CONST PVOID* g_ppfnRtlUserThreadStart

.CODE

; VOID NTAPI Hooked_RtlUserThreadStart(_In_ PUSER_THREAD_START_ROUTINE Function, _In_ PVOID Parameter)
; eax = (PTHREAD_START_ROUTINE)pfnStartAddr
; ebx = (PVOID)pvParam
$PUBLIC_LABEL Hooked_RtlUserThreadStart@8
    ALIGN 16
    push eax
    invoke PA_Event_NewThreadStart, eax
    .IF eax >= 0
	    mov eax, g_ppfnRtlUserThreadStart
		mov eax, [eax]
		xchg eax, [esp]
        retn
    .ELSE
        invoke RtlExitUserThread, eax
    .ENDIF
    ; __fastfail, should not reach here
    xor ecx, ecx
    int 29h

ENDIF ; _M_IX86

    END
