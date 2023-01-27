// solution3.c
// xcrun -sdk macosx clang -arch arm64 solution3.c -O0 -shared -o /tmp/solution3.dylib -mmacosx-version-min=12.6 -Wl,-U,__mh_execute_header,-U,_security_check
#include <stdio.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <mach/mach.h>
#include <mach-o/getsect.h>

extern void* _mh_execute_header;
extern int security_check();

#define HANDLE_ERR(E) {\
  if ((E)) printf("Error: %d, %s @ %s:%d\n", (E), mach_error_string((E)), __FUNCTION__, __LINE__);}

int my_security_check(void) {
    printf("interposed security_check! returning match\n");
    return 1;
}

__attribute__((constructor)) static void oninit() { // 1
    uintptr_t start = (uintptr_t)&_mh_execute_header; // 2
    uintptr_t resolved = 0;
    size_t sz = 0;

    // 3
    uintptr_t* got = (void*)getsectiondata((void*)&_mh_execute_header, "__DATA_CONST", "__got", &sz);
    for (int i = 0; i < sz / 8; i++) {
        if (got[i] == (uintptr_t)security_check) {
            resolved = (uintptr_t)&got[i];
            break;
        }
    }

    if (!resolved) {
        printf("Couldn't find security_check, bailing\n");
        return;
    }

    printf("start is 0x%012lx, patching offset 0x%012lx\n", start, resolved);

     // 4
    task_t task = mach_task_self();
    HANDLE_ERR(vm_protect(task, resolved, 8, FALSE, VM_PROT_READ|VM_PROT_WRITE));

    // 5
    uintptr_t my_security_check_ptr = (uintptr_t)my_security_check;
    HANDLE_ERR(vm_write(task, resolved, (vm_offset_t)&my_security_check_ptr, 8));

    // 6
    HANDLE_ERR(vm_protect(task, resolved, 8, FALSE, VM_PROT_READ));
}
