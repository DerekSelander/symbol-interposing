// solution5.c
// xcrun -sdk macosx clang -arch arm64 solution5.c -O0 -shared -o /tmp/solution5.dylib -mmacosx-version-min=12.6 -Wl,-U,__mh_execute_header
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <mach/mach.h>
#include <pthread.h>
#include <mach-o/ldsyms.h>
#include <mach-o/getsect.h>
#include <assert.h>

#define HANDLE_ERR(E) {\
  if ((E)) printf("Error: %d, %s @ %s:%d\n", (E), mach_error_string((E)), __FUNCTION__, __LINE__);}

// 1 
#pragma pack(push, 4)
typedef struct {
    mach_msg_header_t Head;
    /* start of the kernel processed data */
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    /* end of the kernel processed data */
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    int64_t code[2];
} exc_req;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} exc_resp;
#pragma pack(pop)

// 2
typedef struct {
    uint32_t reg      :  5;
    uint32_t val      : 19;
    uint32_t isnz     :  1; // 1 for cbnz 0 for cbz
    uint32_t op       :  6; // must be 0b011010
    uint32_t is64bit  :  1; // 1 if x[VAL], 0 if w[VAL] for reg
} cbz_op;

#define IS_COMPARE_OP(X) ((X).op == 0b011010 && (X).isnz == 1 )

#define S_USER                  ((uint32_t)(2u << 1))
#define BCR_ENABLE              ((uint32_t)(1u))
#define SS_ENABLE               ((uint32_t)(1u))

static mach_port_t exc_port = MACH_PORT_NULL;
static uintptr_t main_addr = 0;
void* server_thread(void *arg);

__attribute__((constructor)) static void oninit() {
    
    // 3
    const struct mach_header_64 *header = &_mh_execute_header;
    char *cur = (char*)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command *cmd = (void*)cur;
        if (cmd->cmd == LC_MAIN) {
            struct entry_point_command *entry =  (void*)cmd;
             main_addr = (uintptr_t)&_mh_execute_header + entry->entryoff;
            break;
        }
        cur += cmd->cmdsize;
    }
    if (!main_addr) {
        printf("couldn't find entrypoint\n");
        return;
    }
    
    // 4
    mach_port_options_t options = {.flags = MPO_INSERT_SEND_RIGHT};
    HANDLE_ERR(mach_port_construct(mach_task_self(), &options, 0, &exc_port));
    HANDLE_ERR(task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, exc_port, EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES, THREAD_STATE_NONE));
    printf("Exception port setup with port %d\n", exc_port);
    
    
    // 5
    arm_debug_state64_t dbg = {};
    mach_msg_type_number_t cnt = ARM_DEBUG_STATE64_COUNT;
    HANDLE_ERR(thread_get_state(mach_thread_self(), ARM_DEBUG_STATE64, (thread_state_t)&dbg, &cnt));
    dbg.__bvr[0] = (__int64_t)main_addr;
    dbg.__bcr[0] = S_USER|BCR_ENABLE;
    HANDLE_ERR(thread_set_state(mach_thread_self(), ARM_DEBUG_STATE64, (thread_state_t)&dbg, cnt));

    printf("Breakpoint set on main 0x%012lx (offset 0x%06lx)\n", main_addr, main_addr - (uintptr_t)&_mh_execute_header);

    // 6
    static pthread_t exception_thread;
    if (pthread_create(&exception_thread, NULL, server_thread, &exc_port)) {
        return;
    }
    pthread_detach(exception_thread);
    usleep(500);
}

void* server_thread(void *arg) {

    // 1
    const struct section_64 *section = getsectbynamefromheader_64(&_mh_execute_header, "__TEXT", "__text");
    uint64_t text_start = (uintptr_t)&_mh_execute_header + section->offset;
    uint64_t text_sz = section->size;
    bool success = false;
    kern_return_t kr;
    char buffer[0x400] = {};

    pthread_setname_np("Exception Handler");
    printf("exception server starting\n");

    while(1) {
        // 2
        mach_msg_header_t *msg = (void*)buffer;
        msg->msgh_remote_port = MACH_PORT_NULL;
        msg->msgh_id = 2405;
        msg->msgh_local_port = exc_port;
        msg->msgh_size = 0x400;
        if ((kr = mach_msg_receive(msg))) {
            HANDLE_ERR(kr);
            break;
        }

        exc_req *req = (void*)buffer;
        thread_t thread = req->thread.name;

        // 3
        arm_thread_state64_t state = {};
        mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
        HANDLE_ERR(thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count));

        // 4
#if __has_feature(ptrauth_calls)
        uintptr_t pc = (uintptr_t)ptrauth_strip(state.__opaque_pc, ptrauth_key_function_pointer);
#else
        uintptr_t pc = state.__pc;
#endif
        // 5
        arm_debug_state64_t dbg = {};
        mach_msg_type_number_t dbg_cnt = ARM_DEBUG_STATE64_COUNT;
        HANDLE_ERR(thread_get_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, &dbg_cnt));

        if (!success) {
            dbg.__mdscr_el1 |= SS_ENABLE; // enables instruction single step
            dbg.__bcr[0] = 0;
            dbg.__bvr[0] = 0;
            HANDLE_ERR(thread_set_state(thread, ARM_DEBUG_STATE64, (thread_state_t)&dbg, ARM_DEBUG_STATE64_COUNT));
        }


        if (text_start <= pc && pc < text_start + text_sz) {

            // 6
            cbz_op opcode = {};
            assert(sizeof(opcode) == sizeof(uint32_t));
            vm_size_t cnt = 4;
            HANDLE_ERR(vm_read_overwrite(req->task.name, pc, cnt, (vm_address_t)&opcode, &cnt));
            if (IS_COMPARE_OP(opcode)) {
                printf("Patching register x%d at address 0x%012lx (0x%06lx)\n", opcode.reg, pc, pc - (uintptr_t)&_mh_execute_header);
                state.__x[opcode.reg] = 0;
                HANDLE_ERR(thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT));
                success = true;
            }
        }

        // 7
        msg->msgh_local_port = MACH_PORT_NULL;
        msg->msgh_bits = MACH_RCV_MSG | MACH_SEND_TIMEOUT;
        msg->msgh_id = 2505;
        msg->msgh_size = sizeof(exc_resp);
        exc_resp *resp = (exc_resp*)msg;
        resp->NDR = NDR_record;
        resp->RetCode = KERN_SUCCESS;
        if ((kr = mach_msg_send(msg))) {
            HANDLE_ERR(kr);
            break;
        }
    }
    return NULL;
}
