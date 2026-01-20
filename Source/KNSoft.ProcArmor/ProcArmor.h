#pragma once

#include <Windows.h>

#define PA_VERSION 0

typedef struct _PA_INIT
{
    ULONG Version;    // PA_VERSION
    struct
    {
        ULONG Frequence : 4;    // 0 (disable), or 1 (low) to 15 (high)
    } RuntimeCheck;
    struct
    {
        ULONG Enable : 1;   // Anti runtime debuggers
    } AntiDebug;
    struct
    {
        ULONG KDDetect : 1;             // Detect system Kernel-Debug is enabled or not
        ULONG TestingModeDetect : 1;    // Detect system testing mode is enabled or not
        ULONG VMDetect : 1;             // Detect virtual machine environment
        ULONG SandboxDetect : 1;        // Detect sandbox environment
    } Environment;
    struct
    {
        ULONG AntiRemoteCall : 1;   // Anti remote DLL load API calls (include APCs)
        ULONG AntiWindowHook : 1;   // Anti window message or event hook
    } AntiDLLAttach;
    struct
    {
        ULONG BlockDynamicCode : 1;
    } Integrity;
    struct
    {
        ULONG EnhanceHeapChecks : 1;    // Enable more heap checks and the terminate-on-corruption feature
        ULONG PreferSegmentHeap : 1;    // Prefer segment heap if available
    } SecureHeap;
} PA_INIT, *PPA_INIT;

/* Default configuration */
#define PA_INIT_DEFAULT { PA_VERSION, { 4 }, { TRUE }, { FALSE, FALSE, FALSE, FALSE }, { TRUE, TRUE }, { TRUE }, { TRUE, FALSE } }

/* For development environment, debugger and VM are allowed */
#define PA_INIT_DEVELOPMENT { PA_VERSION, { 4 }, { FALSE }, { FALSE, FALSE, FALSE, FALSE }, { TRUE, TRUE }, { TRUE }, { TRUE, FALSE } }

/* For development environment, debugger is allowed */
#define PA_INIT_DEBUG { PA_VERSION, { 4 }, { FALSE }, { FALSE, FALSE, TRUE, TRUE }, { TRUE, TRUE }, { TRUE }, { TRUE, FALSE } }

/* Enable all protections */
#define PA_INIT_FULL { PA_VERSION, { 8 }, { TRUE }, { TRUE, TRUE, TRUE, TRUE }, { TRUE, TRUE }, { TRUE }, { TRUE, TRUE } }

/* Must success, or terminate immediately */
DECLSPEC_EXPORT
VOID
APIENTRY
PA_Initialize(
    _In_ PPA_INIT Init);
