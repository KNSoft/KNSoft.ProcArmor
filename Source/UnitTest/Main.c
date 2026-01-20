#include "UnitTest.h"

#include <KNSoft/NDK/Package/UnitTest.inl>

DECLSPEC_EXPORT PA_INIT PA_Init = PA_INIT_DEBUG;

TEST_DECL_FUNC(RemoteThreadDllAttach);

CONST UNITTEST_ENTRY UnitTestList[] = {
    TEST_DECL_ENTRY(RemoteThreadDllAttach),
    { 0 }
};

int
_cdecl
wmain(
    _In_ int argc,
    _In_reads_(argc) _Pre_z_ wchar_t** argv)
{
    PA_Initialize(&PA_Init);
    return UnitTest_Main(argc, argv);
}
