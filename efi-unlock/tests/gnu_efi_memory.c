/* Native Linux regression check; uses the installed gnu-efi archives.
 * gcc -O2 -fshort-wchar -maccumulate-outgoing-args -DGNU_EFI_USE_MS_ABI \
 *   -I/usr/include/efi -I/usr/include/efi/x86_64 efi-unlock/tests/gnu_efi_memory.c \
 *   -Wl,--start-group -lefi -lgnuefi -Wl,--end-group -o /tmp/efi-memory-check
 */
#include <efi.h>
#include <efilib.h>
#include <assert.h>
#include <stdio.h>
int main(void) {
    static UINT8 source[65536],dest[65536];
    for (UINTN i=0;i<sizeof(source);i++) source[i]=(UINT8)(i*37U+11U);
    SetMem(dest,sizeof(dest),0xa5);
    for (UINTN i=0;i<sizeof(dest);i++) assert(dest[i]==0xa5);
    CopyMem(dest,source,sizeof(dest));
    assert(CompareMem(dest,source,sizeof(dest))==0);
    puts("PASS: direct GNU-EFI memory calls use the correct header-selected ABI");
}
