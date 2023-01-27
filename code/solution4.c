// solution4.c
// xcrun -sdk macosx clang -arch arm64 solution4.c -O0 -shared -o /tmp/solution4.dylib -mmacosx-version-min=12.6 -Wl,-U,_security_check
#include <stdio.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <assert.h>

extern int security_check(void);

#define HANDLE_ERR(E) {\
  if ((E)) printf("Error: %d, %s @ %s:%d\n", (E), mach_error_string((E)), __FUNCTION__, __LINE__);}

int my_security_check(void) {
    printf("interposed security_check! returning success\n");
    return 1;
}

uint32_t CREATE_ADRP_OP(uint8_t reg, uintptr_t start_addr, uintptr_t dest_addr) { // 1
    typedef struct {
        uint32_t reg      :  5; //
        uint32_t val      : 18; //
        uint32_t negative :  1; // If true everything will need to be 2's complement including val2bits
        uint32_t op2      :  5; // must be 0b10000
        uint32_t val2bits :  2; // The lower 2 bits of a value (if any) are stored here
        uint32_t op       :  1; // must be 1
    } ardp_op;
    uint32_t op = 0;
    assert(sizeof(ardp_op) == sizeof(uint32_t));
    ardp_op *a = (void*)&op;
    a->op = 1;
    a->op2 = 0b10000;
    uintptr_t mask = ~((uintptr_t)0xfff);
    int32_t offset = ((int32_t)((dest_addr & mask) - (start_addr & mask))) / 4096;
    a->negative = offset < 0 ? 1 : 0;
    a->reg = reg;
    a->val2bits = (offset & 3);
    // Remaing val contains bit 3 and on, throw away first 2 bits
    a->val = (offset >> 2);
    return op;
}

uint32_t CREATE_BR_OP(uint8_t dreg) {
    typedef struct {
        uint32_t unused    :  5; // 0
        uint32_t dreg      :  5; // Which register to branch to
        uint32_t op        : 22; // Should be 0b1101011000011111000000
    } brreg_op;
    uint32_t op = 0;
    assert(sizeof(brreg_op) == sizeof(uint32_t));
    brreg_op *a = (void*)&op;
    a->op = 0b1101011000011111000000;
    a->dreg = dreg;
    return op;
}

uint32_t CREATE_ADD_OP(uint8_t dreg, uint8_t sreg, int16_t val, bool lslshift) { // 2
    typedef struct {
        uint32_t dreg     :  5; // destination register
        uint32_t sreg     :  5; // source register
        uint32_t val      : 12; // val to be added, i.e. x4 = x6 + 0x123
        uint32_t lsl      :  1; // #lsl #12 to val
        uint32_t op2      :  7; // Should be 0b01000100
        uint32_t negative :  1; // 1 if negative
        uint32_t op       :  1; // Should be 0b1
    } add_op;
    uint32_t op = 0;
    assert(sizeof(add_op) == sizeof(uint32_t));
    add_op *a = (void*)&op;
    a->op = 1;
    a->lsl = lslshift;
    a->op2 = 0b0100010;
    a->dreg = dreg;
    a->sreg = sreg;
    a->val = val;
    a->negative = val < 0 ? 1 : 0;
    return op;
}

__attribute__((constructor)) static void oninit() {    
    vm_address_t security_check_ptr = (vm_address_t)security_check;
    vm_address_t my_security_check_ptr = (vm_address_t)my_security_check;
    printf("attempting to patch security_check @ 0x%012lx with my_security_check 0x%012lx\n",  security_check_ptr, my_security_check_ptr);
    
    // 3 
    char shellcode[12] = {};
    uint8_t reg8 = 8;
    uint32_t adrpop = CREATE_ADRP_OP(reg8, security_check_ptr, my_security_check_ptr);
    uint32_t addop = CREATE_ADD_OP(reg8, reg8, (uintptr_t)my_security_check_ptr & 0xfff, 0);
    uint32_t brop = CREATE_BR_OP(reg8);
    memcpy((void*)&shellcode[0], &adrpop, 4);
    memcpy((void*)&shellcode[4], &addop, 4);
    memcpy((void*)&shellcode[8], &brop, 4);
    
    // 4
    task_t task = mach_task_self(); 
    kern_return_t kr = vm_protect(task, security_check_ptr, 12, FALSE, VM_PROT_READ|VM_PROT_WRITE);
    if (kr) { // If we get an error it's likely because of copy on write protection
        kr = vm_protect(task, security_check_ptr, 12, FALSE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
    }
    HANDLE_ERR(kr);

    // 5
    HANDLE_ERR(vm_write(task, security_check_ptr, (vm_offset_t)&shellcode, 12));
    kr = vm_protect(task, security_check_ptr, 12, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr) {
        kr = vm_protect(task, security_check_ptr, 12, FALSE, VM_PROT_READ | VM_PROT_EXECUTE|VM_PROT_COPY);
    }
    HANDLE_ERR(kr);
}
