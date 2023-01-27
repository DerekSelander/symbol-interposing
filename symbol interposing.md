# Chapter 16: Symbol Interposing & Hooking Shenanigans

Let's play a game: A series of code snippets and how they are compiled will be presented. In each code snippet, a challenge is given to execute a certain function that should be inaccessible unless you know the password. In order to execute this privileged function, you're not allowed to alter the source code nor how it's compiled in any way. Fortunately, you can assume that you have code execution in a dynamic library running in the same address space and loaded in via the `DYLD_INSERT_LIBRARIES` environment variable.

For these challenges, all executables are compiled and run on an Apple macOS Monterey operating system with hardware capable of running ARM64/ARM64e. Since Apple is transitioning away from Intel in their device lineup, only ARM64 & ARM64e will be covered. clang-1400.0.29.102 is used for all examples and was tested on a macOS 12.6 M1 machine.

This writeup assumes you have an understanding of the C language as well several Apple concepts. If you're unfamiliar with Mach-O load commands and the symbol table, you're encouraged to read about those first by [googling](https://www.google.com/search?q=macho+load+commands) or looking up the [&lt;mach-o/loader.h&gt;](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h) & [&lt;mach-o/nlist.h&gt;](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/nlist.h) headers. **No Objective-C/Swift swizzling is covered here. That story has been so done already**

Sounds good? Game on? 

## Challenge 1: warm-up

*Given the following C snippet which produces the `ex1` executable, execute the `do_the_thing()` function before the program completes.*

```c
// ex1.c 
// xcrun -sdk macosx clang -arch arm64 ex1.c -o /tmp/ex1 -O0 -mmacosx-version-min=12.6

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <CommonCrypto/CommonCrypto.h>

char g_secret[CC_MD5_DIGEST_LENGTH] = "\x5f\x4d\xcc\x3b\x5a\xa7\x65\xd6"
                                      "\x1d\x83\x27\xde\xb8\x82\xcf\x99"; // "password"

int security_check(const char *password) {
    char result[CC_MD5_DIGEST_LENGTH];
    if (!password) {
        return 0;
    }
    CC_MD5(password, strlen(password), (unsigned char*)result); 
    return memcmp(result, g_secret, CC_MD5_DIGEST_LENGTH) == 0;
}

void do_the_thing(void) {
    printf("🌈success!🌈\n");
}

int main(int argc, const char* argv[]) {
    if (security_check(argc > 1 ? argv[1] : NULL)) {
        do_the_thing();
    }
    return 0;
}
```

This snippet of code checks for a passphrase that's passed in as an argument over the command line. If there is an argument, the passphrase is passed into `security_check(const char*)`. If the MD5 hash matches a hardcoded hash (which is derived from the phrase "password"), then the `do_the_thing()` function is invoked. Per the "rules" of the challenge, the compilation flags found at the beginning of the source code must be used to create the `ex1` executable.

```bash
~ cp ex1.c /tmp/
~ cd /tmp/
~ xcrun -sdk macosx clang -arch arm64 ex1.c -o /tmp/ex1 -O0 -mmacosx-version-min=12.6
~ ex1 test
~ ex1 password
🌈success!🌈
```

**Assessment** There's a number of hooking points that could be used coherence this code into calling `do_the_thing()`. Fortunately, it is straightforward to be able to call the `do_the_thing()` symbol directly. There's no symbol stripping and `do_the_thing()` is exported as a global symbol. This means other loaded executable frameworks or dylibs, also known as **images**, can reference it by name, using either an `extern` declaration or using the `dlopen`/`dlsym` combo.

Here's a solution which calls the `do_the_thing()` function directly before the program completes:

```c
// solution1.c
// xcrun -sdk macosx clang -arch arm64 solution1.c -O0 -shared -o /tmp/solution1.dylib -Wl,-U,_do_the_thing  -mmacosx-version-min=12.6 # 1
__attribute__((destructor)) void deinit(void) { // 2
    extern void do_the_thing(void);
    do_the_thing();
}
```

Comments are added to the code to highlight points of interest.

1. When compiling, the `-Wl,-U,_do_the_thing` flag instructs the linker (via the `-Wl,..` part) to ignore any undefined references to the `do_the_thing()` symbol. With Apple, any C function will have an underscore prepended to the symbol name. Typically, an executable calls into a dynamic library and will link to it. For this case, the dynamic library is calling into the executable without linking to it. 
2. The function is marked up with the **`__attribute__((destructor))`**, which tells `dyld` to call this block of code before the image is unloaded. This means that the code will execute after the `main` function completes. 


Once compiled, you can see the solution in action via the `DYLD_INSERT_LIBRARIES` environment variable applied to `ex1`.

```bash
~ DYLD_INSERT_LIBRARIES=/tmp/solution1.dylib /tmp/ex1
🌈success!🌈
```

For those unfamiliar with `DYLD_INSERT_LIBRARIES`, it will load code into a process before anything else gets loaded. This is contingent on process permissions and security settings (i.e. [`-Wl,-add_empty_section,__
RESTRICT,__restrict`](https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/dyld/DyldProcessConfig.cpp#L706)). One would need to disable Apple's System Integrity Permission to be able to use `DYLD_INSERT_LIBRARIES` on an Apple executable.

With the warmup completed and the rules established, let's move on to something a bit more exciting.

## Challenge 2: dyld interposing

*Given the following snippet which produces `ex2`, execute the `do_the_thing()` function before the program completes via any means necessary.*

```c
// ex2.c 
// xcrun -sdk macosx clang -arch arm64 ex2.c -o /tmp/ex2 -O0 -mmacosx-version-min=12.6

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <CommonCrypto/CommonCrypto.h>

char g_secret[CC_MD5_DIGEST_LENGTH] = "\x5f\x4d\xcc\x3b\x5a\xa7\x65\xd6"
                                      "\x1d\x83\x27\xde\xb8\x82\xcf\x99";

int security_check(const char *password) {
    char result[CC_MD5_DIGEST_LENGTH];
    if (!password) {
        return 0;
    }
    CC_MD5(password, strlen(password), (unsigned char*)result); 
    return memcmp(result, g_secret, CC_MD5_DIGEST_LENGTH) == 0;
}

static void do_the_thing(void) { // 1
    printf("🌈success!🌈\n");
}

int main(int argc, const char* argv[]) {
    if (security_check(argc > 1 ? argv[1] : NULL)) {
        do_the_thing();
    }
    return 0;
}
```

**Assessment** It looks like the authors caught on to how trivial it is to directly call the `do_the_thing()` function and have added a `static` declaration to `do_the_thing()`. This is the only change between `ex1.c` and `ex2.c`. This makes it so `do_the_thing()` is not a globally exported symbol and can not be directly referenced by other images. If this code were to run with the previous solution, the following crash would occur:

```bash
~ xcrun -sdk macosx clang -arch arm64 ex2.c -o /tmp/ex2 -O0 -mmacosx-version-min=12.6 -Wno-deprecated-declarations

~ DYLD_INSERT_LIBRARIES=/tmp/solution1.dylib /tmp/ex2
dyld[14227]: symbol not found in flat namespace (_do_the_thing)
[1]    14227 abort      DYLD_INSERT_LIBRARIES=/tmp/solution.dylib /tmp/ex2
```

> **NOTE:** Even with the `static` declaration, it's still possible to directly call the `do_the_thing()` function. The function is still referenced by name in the symbol table and can be accessed through other means.  However, in order to showcase different techniques, assume that there's no easy way to directly execute `do_the_thing()` and alternative methods must be explored.

One such method is **symbol interposing**, which allows replacing a reference to a symbol with another. Symbol interposing can be used to alter parameters, return values, or even completely replace the symbol. This is typically done through undefined external references to symbols, which are implemented in other images than the one referencing them. Examining the undefined exported symbols can provide insight into potential avenues for interposing.

For example, upon examining the external symbols compiled into `ex2`, several potential interposing solutions can be implemented to augment execution control and allow the `do_the_thing()` function to execute. These include:

```
~ nm -mu /tmp/ex2
                 (undefined) external _CC_MD5 (from libSystem)
                 (undefined) external ___stack_chk_fail (from libSystem)
                 (undefined) external ___stack_chk_guard (from libSystem)
                 (undefined) external _memcmp (from libSystem)
                 (undefined) external _printf (from libSystem)
                 (undefined) external _strlen (from libSystem)
```

Upon looking at the external symbols compiled into `ex2`, there are several potential interposing solutions which could augment execution control allowing the  `do_the_thing()` function to execute. Here's an idea for each relevant symbol if it were to be replaced:

* Replacing the `CC_MD5` symbol to match the "password" hash, so the `memcmp` check succeeds.
* Interposing `memcmp` to return 0, so the 2 values are believed to be equal, resulting in the conditional check succeeding and executing `do_the_thing()`.
* Interposing `strlen` to directly call the address of the `do_the_thing()` symbol by walking the symbol table and determining the load address. This technique can actually be applied to any of the above symbols with some caveats that are discussed below.

Given these options, the `memcmp` path is preferred for its simplicity. Here's a solution that interposes all external references to `memcmp` making every comparison believed to be equal.

```c
// solution2.c
// xcrun -sdk macosx clang -arch arm64 solution2.c -O0 -shared -o /tmp/solution2.dylib -mmacosx-version-min=12.6
#include <stdio.h>
#include <string.h> // memcmp

int my_memcmp(const void *s1, const void *s2, size_t n) { // 1
    printf("interposed! returning match\n");
    return 0;
}

__attribute__((used, section("__DATA,__interpose"))) // 2
    static void* interpose[] = {my_memcmp, memcmp};
```

1. `my_memcmp` is declared which will stand in for the real `memcmp` and always return a matching comparison.
2. The `interpose` array contains references to the `my_memcmp` and `memcmp` and has 2 compiler attributes. The first one, `used`, tells the compiler not to optimize out this declaration since it's not referenced elsewhere. This is a bit superfluous as this is compiled with no optimizations (`-O0`). The second attribute, `section("__DATA,__interpose")`, will put the contents of the `interpose` array into the specified Mach-O section. Mach-O load commands are outside the scope of this tutorial but you can [find many tutorials](https://www.google.com/search?q=macho+load+commands) around the internet. Upon loading an image, `dyld` will inspect the Mach-O load commands. If dyld sees a Mach-O section called `__interpose` in the `__DATA` segment, dyld will attempt to interpose the declared symbols on any future images that are loaded into the process. More than one pair of symbols can be provided. Be aware that `dyld` consults AMFI flags which can prevent interposing on certain processes.

Although not included in the above code, `dyld` offers a convenient C define macro which can be found [here](https://github.com/apple-oss-distributions/dyld/blob/c8a445f88f9fc1713db34674e79b00e30723e79d/include/mach-o/dyld-interposing.h#L43-L45) which does the same thing as the above declared attribute values in a more friendly API.

With the `solution2.dylib` compiled, you can see `memcmp` being interposed in `ex2` **provided `ex2` gets an argument**.


```bash
~ xcrun -sdk macosx clang -arch arm64 solution2.c -O0 -shared -o /tmp/solution2.dylib -mmacosx-version-min=12.6
~ DYLD_INSERT_LIBRARIES=/tmp/solution2.dylib /tmp/ex2 muwahahahaa
interposed! returning match
🌈success!🌈
```

You can see exactly what's happening during symbol interposing by adding the undocumented **`DYLD_PRINT_INTERPOSING`** environment variable. Adding `DYLD_PRINT_INTERPOSING` to the previous command produces the following output on this machine:

```bash
DYLD_PRINT_INTERPOSING=1  DYLD_INSERT_LIBRARIES=/tmp/solution2.dylib /tmp/ex2 muwahahahaa
dyld[26035]: solution2.dylib has interposed '_memcmp' to replacing binds to 0x182F8CCB0 with 0x1002A3F58
dyld[26035]:   interpose replaced 0x182F8CCB0 with 0x182F8CCB0 in /private/tmp/solution2.dylib
dyld[26035]:   interpose replaced 0x182F8CCB0 with 0x1002A3F58 in /private/tmp/ex2
dyld[26035]: interpose: *0x1dd078880 = 0x1002a3f58 (JOP: diversity 0x0000, addr-div=1, key=IA)
dyld[26035]: interpose: *0x1dd07e818 = 0x1002a3f58 (JOP: diversity 0x0000, addr-div=1, key=IA)
dyld[26035]: interpose: *0x1dd07fe90 = 0x1002a3f58 (JOP: diversity 0x0000, addr-div=1, key=IA)
dyld[26035]: interpose: *0x1dd0951c0 = 0x1002a3f58 (JOP: diversity 0x0000, addr-div=1, key=IA)
...
```

In the above output, the original `memcmp`'s address is `0x182F8CCB0` and the new `my_memcmp`'s address is `0x1002A3F58`

With ~540 lines omitted in the output above, it's easy to see that the `memcmp` function is heavily referenced across all the loaded images in the `ex2` process. This brings up an interesting component in interposing. Some interposing solutions will work across every single image that's loaded into a process, while other solutions will only work on a per image basis. The `__DATA,__interpose` trick will work on every loaded image that is loaded after the interpose load command.

>**NOTE:** One must be careful when replacing an undefined symbol across all images because critical logic could be altered elsewhere. For that reason, the caller's address should be checked via `__builtin_return_address(0)` to see if it's coming from `ex2` or `my_memcmp` should only augment control depending upon the parameters. Another idea is to only interpose on a per-image basis.

## Challenge 3: (fish)hooking stubs

*Using the same code snippet from the previous example, execute the `do_the_things` symbol through whatever means. This time, you're only allowed to interpose symbols declared in `ex3.c`*
```c
// ex3.c 
// xcrun -sdk macosx clang -arch arm64 ex3.c -o /tmp/ex3 -O0 -mmacosx-version-min=12.6 -Wl,-interposable

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <CommonCrypto/CommonCrypto.h>

char g_secret[CC_MD5_DIGEST_LENGTH] = "\x5f\x4d\xcc\x3b\x5a\xa7\x65\xd6"
                                      "\x1d\x83\x27\xde\xb8\x82\xcf\x99";

int security_check(const char *password) {
    char result[CC_MD5_DIGEST_LENGTH];
    if (!password) {
        return 0;
    }
    CC_MD5(password, strlen(password), (unsigned char*)result); 
    return memcmp(result, g_secret, CC_MD5_DIGEST_LENGTH) == 0;
}

static void do_the_thing(void) { // 1
    printf("🌈success!🌈\n");
}

int main(int argc, const char* argv[]) {
    if (security_check(argc > 1 ? argv[1] : NULL)) {
         do_the_thing();
    }
    return 0;
}
```

**Assessment** Nothing has changed from the code between `ex2.c` and `ex3.c`. The main difference is a newly added `-interposable` linker compilation flag and the challenge restricting to only interposing local symbols. 

Compile and dump the potential options for interposing symbols on `ex3`:

```bash
~ xcrun -sdk macosx clang -arch arm64 ex3.c -o /tmp/ex3 -O0 -mmacosx-version-min=12.6 -Wno-deprecated-declarations -Wl,-interposable
~ nm /tmp/ex3 -Ug
0000000100000000 T __mh_execute_header
0000000100008000 D _g_secret
0000000100003edc T _main
0000000100003e20 T _security_check
```

Looks like `g_secret`, `main`, and `security_check` are potential avenues for interposing. From the challenge's compilation source, there's a very interesting linker flag that's included called **`-interposable`**

As you saw earlier, undefined symbols can be bound at symbol lookup or upon module load. Typically, local symbols in the same image do not need to be bound lazily or at load time because the linker can resolve those symbols via relative offsets. However, it's possible to overwrite this setting through the `-interposable` flag.

### Symbol Binding Detour

Public solutions exist to interpose symbols on a per image basis. One of the more popular repos is Facebook's [fishhook](https://github.com/facebook/fishhook) which targets **lazy symbol binding**. Lazy symbol binding is the process in which an external symbol is bound upon the first time it is referenced in an image instead of when the image gets loaded. Although the [How it works](https://github.com/facebook/fishhook/blob/main/README.md#how-it-works) section provides an excellent overview, a lower level dive might be insightful. A detour will be taken to showcase how `printf` gets bound into `ex3`.

Compile `ex3.c`'s source with ld's `-interposable` option.

```bash
~ xcrun -sdk macosx clang -arch arm64 ex3.c -o /tmp/ex3 -O0 -mmacosx-version-min=12.6 -Wno-deprecated-declarations -Wl,-interposable
```

Then run Apple's preferred debugger, `lldb`, on the `ex3` executable:

```bash
~ lldb /tmp/ex3
(lldb) target create "ex3"
Current executable set to '/tmp/ex3' (arm64).
```

At this point, `lldb` has not launched `ex3`, so the process layout still matches the `ex3` file layout on disk. No binding operations have happened at this point.

Dump the assembly to `do_the_thing()` which calls `printf`:

```lldb
(lldb) disassemble -n do_the_thing
ex3`do_the_thing:
ex3[0x100003f40] <+0>:  stp    x29, x30, [sp, #-0x10]!
ex3[0x100003f44] <+4>:  mov    x29, sp
ex3[0x100003f48] <+8>:  adrp   x0, 0
ex3[0x100003f4c] <+12>: add    x0, x0, #0xfa4            ; "\xf0\x9f\x8c\x88success!\xf0\x9f\x8c\x88\n"
ex3[0x100003f50] <+16>: bl     0x100003f80               ; symbol stub for: printf
ex3[0x100003f54] <+20>: ldp    x29, x30, [sp], #0x10
ex3[0x100003f58] <+24>: ret
```

Looking at the disassembly comments, there's a branch call to address **`0x100003f80`** for `printf`. Further information about the `0x100003f80` address can be queried via `lldb`'s `image lookup` command:

```lldb
(lldb) image lookup -a 0x100003f80
      Address: ex3[0x0000000100003f80] (ex3.__TEXT.__stubs + 36)
      Summary: ex3`symbol stub for: printf
```

This jumps to an internal Mach-O section in `ex3` called **`__stubs`** found in the `__TEXT` segment. Disassembling this address produces the following relevant info:

```lldb
(lldb) x/3i 0x100003f88
0x100003f80: 0xb0000010   adrp   x16, 1
0x100003f84: 0xf9401210   ldr    x16, [x16, #0x20]
0x100003f88: 0xd61f0200   br     x16
```

Breaking these instructions down: 
* `adrp   x16, 1` - Load the next 4KB page into `x16` relative to the 4KB floor of program counter, for this unslid address it would be: `x16 = 0x100004000` (with the 4KB floor of the program counter being `0x100003000`)
* `ldr    x16, [x16, #0x20]`  Add 0x20 to `x16` then dereference and store into `x16`: `x16 = *(x16 + 0x20)`
* `br     x16`: Call the code at `x16` (`0x100004020`)

So what is at **`0x100004020`**?

```lldb
(lldb) image lookup -a 0x100004020
      Address: ex3[0x0000000100004020] (ex3.__DATA_CONST.__got + 32)
      Summary: (void *)0x8010000000000004
(lldb) x/i 0x100004020
0x100004020: 0x00000004   udf    #0x4
```

**`__DATA_CONST.__got`** is the containing Mach-O section for address `0x100004020`. The `udf` assembly instruction found here would cause the program to throw an exception and crash. This means something gets modified from the point when `ex3` is on disk to the point where `ex3` is running. Fortunately, `dyld` has another environment variable to see what's happening during binding, **`DYLD_PRINT_BINDINGS`**.

The debug session below demonstrates how to use `lldb` to set a breakpoint on `main` and examine relevant binding contents while also displaying the `dyld` environment variable.

```lldb
(lldb) b main
Breakpoint 1: where = ex3`main, address = 0x0000000100003ed4

(lldb) process launch -E DYLD_PRINT_BINDINGS=1 -- password
Process 11633 launched: '/tmp/ex3' (arm64)
dyld[11633]: <ex3/bind#0> -> 0x18da961c4 (libcommonCrypto.dylib/_CC_MD5)
dyld[11633]: <ex3/bind#1> -> 0x182ea3ce8 (libsystem_c.dylib/___stack_chk_fail)
dyld[11633]: <ex3/bind#2> -> 0x1dbed5798 (libsystem_c.dylib/___stack_chk_guard)
dyld[11633]: <ex3/bind#3> -> 0x182f8ccb0 (libsystem_platform.dylib/__platform_memcmp)
dyld[11633]: <ex3/bind#4> -> 0x182e68ee8 (libsystem_c.dylib/_printf)
dyld[11633]: <ex3/bind#5> -> 0x182f8c860 (libsystem_platform.dylib/__platform_strlen)
dyld[11633]: fixup: *0x000100004000 = 0x00018DA961C4
dyld[11633]: fixup: *0x000100004008 = 0x000182EA3CE8
dyld[11633]: fixup: *0x000100004010 = 0x0001DBED5798
dyld[11633]: fixup: *0x000100004018 = 0x000182F8CCB0
dyld[11633]: fixup: *0x000100004020 = 0x000182E68EE8
dyld[11633]: fixup: *0x000100004028 = 0x000100003E18
dyld[11633]: fixup: *0x000100004030 = 0x000182F8C860
Process 11633 stopped
...

(lldb) x/gx 0x000100004020               # Inspect post-bound contents at 0x000100004020
0x100004020: 0x0000000182e68ee8

(lldb) memory region 0x000100004020     # Is this memory region writable?
[0x0000000100004000-0x0000000100008000) r-- __DATA_CONST
Modified memory (dirty) page list provided, 1 entries.
Dirty pages: 0x100004000.

(lldb) image lookup -a 0x000182E68EE8.   # Query contents that were dereferenced at 0x000100004020
      Address: libsystem_c.dylib[0x000000018021cee8] (libsystem_c.dylib.__TEXT.__text + 194108)
      Summary: libsystem_c.dylib`printf
```

From the output, one can observe the `0x000100004020` address was bound to `0x000000018021cee8`, the address of `printf`. After the bind has completed, the `__DATA_CONST` Mach-O section gets write access removed so no one can muck around with interposing... but it's still possible to change memory protections using the relevant APIs. 

As you can see, undefined bind on load symbols are resolved and stored into `__DATA_CONST.__got` on ARM64 executables. Using `lldb`, the size and starting address of the `__DATA_CONST.__got` section is displayed:

```lldb
(lldb) image dump section ex3
...
  0x00000005 data-ptrs        [0x0000000100004000-0x0000000100004038)  rw-  0x00004000 0x00000038 0x00000006 ex3.__DATA_CONST.__got
...
``` 

For `ex3`, the `__got` section has a size of `0x38`, with each of these holding a pointer of 8 bytes. This means there are 7 function pointers in the `__got` section:

```lldb
(lldb) x/7gx 0x0000000100004000
0x100004000: 0x000000018da961c4 0x0000000182ea3ce8
0x100004010: 0x00000001dbed5798 0x0000000182f8ccb0
0x100004020: 0x0000000182e68ee8 0x0000000100003e20
0x100004030: 0x0000000182f8c860

# Examining the first address of the 7 pointers...
(lldb)  image lookup -a 0x000000018da961c4
      Address: libcommonCrypto.dylib[0x000000018ae4a1c4] (libcommonCrypto.dylib.__TEXT.__text + 1880)
      Summary: libcommonCrypto.dylib`CC_MD5

# These are bound pointers to undefined symbols
```

The most interesting aspect of this detour is the size and ordering of the function pointers found in `__DATA_CONST.__got` can match up with the ordering of the **indirect symbol table**. The indirect symbol table is an array of `uint32_t`s that point to indices into the actual symbol table array.

The actual symbol table is an array of struct `nlist[_64]`, which is described in [`<mach-o/nlist.h>`](https://github.com/apple-oss-distributions/xnu/blob/5c2921b07a2480ab43ec66f5b9e41cb872bc554f/EXTERNAL_HEADERS/mach-o/nlist.h#L92-L100).

Use `otool -l` to dump the Mach-O commands and search for the relevant `__got/__stubs` content using `grep`.

```bash
 ~ otool -l  /tmp/ex3 | grep -E "(__got|_stubs)" -A10
   sectname __stubs
   segname __TEXT
      addr 0x0000000100003f5c
      size 0x0000000000000048
    offset 16220
     align 2^2 (4)
    reloff 0
    nreloc 0
     flags 0x80000408
 reserved1 0 (index into indirect symbol table) # <--- 
 reserved2 12 (size of stubs)
--
  sectname __got
   segname __DATA_CONST
      addr 0x0000000100004000
      size 0x0000000000000038
    offset 16384
     align 2^3 (8)
    reloff 0
    nreloc 0
     flags 0x00000006
 reserved1 6 (index into indirect symbol table) # <---
 reserved2 0
 ```

From the above `otool` output, `ex3` has an indirect symbol table start index for `__got` at **index 6**, the start index for `__stubs` is **index 0**.

You have the start index, now you need to find the file offset of this `uint32_t` array. This is given by the `indirectsymoff` member in the **`struct dysymtab_command`** from the **`LC_DYSYMTAB`** load command. Using `otool` again and `grep`'ing for `indirectsym` will give the relevant information.

```bash
~ otool -l /tmp/ex3 | grep indirectsym
 indirectsymoff 49592
  nindirectsyms 13
```

The file offset to the `uint32_t` indirect offset array is at **49592** in `ex3` (for this compiled version of `ex3`) whose size is 13 `uint32_t`'s. Dumping the raw bytes gives the following:

```bash
~ xxd -g 4 -e -s 49592 -l $((13 * 4)) /tmp/ex3
0000c1b8: 00000005 00000006 00000008 00000009  ................
0000c1c8: 00000004 0000000a 00000005 00000006  ................
0000c1d8: 00000007 00000008 00000009 00000004  ................
0000c1e8: 0000000a                             ....
```

Breaking down the options `xxd` options:
* `-g 4` - Groups the bytes into a size of 4, which is the size of `uint32_t`.
* `-e` - Dump the bytes in little endian byte format.
* `-s 49592` - Start at offset 49592 from the beginning of the `ex3` file.
* `-l $((13 * 4))` - Dump the size of 13 `uint32_t`s.

The output will dump the full indirect symbol table array. Cross referencing this data matches with the builtin indirect symbol table option `-I` for `otool`.

```
~ otool -I /tmp/ex3
/tmp/ex3:
Indirect symbols for (__TEXT,__stubs) 6 entries
address            index
0x0000000100003f64     5
0x0000000100003f70     6
0x0000000100003f7c     8
0x0000000100003f88     9
0x0000000100003f94     4
0x0000000100003fa0    10
Indirect symbols for (__DATA_CONST,__got) 7 entries
address            index
0x0000000100004000     5
0x0000000100004008     6
0x0000000100004010     7
0x0000000100004018     8
0x0000000100004020     9
0x0000000100004028     4
0x0000000100004030    10
```

Remember how offset 6 was the indirect symbol table start for the `__got` section? This matches the dumped `uint32_t` output from `xxd` to the `otool -I` option. With this information, you can finally dump the symbols to match the indexes!

Using the `-p` option for `nm`, the symbol table can be displayed in sequential order (instead of alphabetical order):

```bash
~ nm -p /tmp/ex3 | nl -v0
     0  0000000100003f40 t _do_the_thing
     1  0000000100000000 T __mh_execute_header
     2  0000000100008000 D _g_secret
     3  0000000100003ed4 T _main
     4  0000000100003e18 T _security_check
     5                   U _CC_MD5
     6                   U ___stack_chk_fail
     7                   U ___stack_chk_guard
     8                   U _memcmp
     9                   U _printf
    10                   U _strlen

```

Recall how `0x0000000100004020` matched to `printf` when exploring `ex3`'s `__DATA_CONST.__got` in `lldb`. You can see that `printf` is at index 9 (starting from 0) in the `nm` ordered output of the symbol table, which matches `otool -I ex3`'s index 9 for address `0x0000000100004020`.

### &lt;/detour&gt;

Coming back to the problem at hand for `ex3` and binding, the `-interpose` option was applied to `ex3` resulting in `security_check` being bound to address `0x0000000100004028` (or equivalent on your build of `ex3`).

The solution needs to find the beginning address to the `main` executable which contains the Mach-O load commands, find the offset to `__DATA_CONST`, make that region of memory writeable, patch the correct `security_check` bind address to a controlled function, and (optionally) make the `__DATA_CONST` segment read only again. Instead of writing lengthy logic to parse Mach-O load commands, a solution will be presented that simply looks in the `__got` section for any pointer to `security_check` and then patch it to a controlled function.


```c
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
```
Breaking down important points:

1.  A **constructor** attribute is used this time, so the `oninit` function is called on image load. This occurs before the `main` function in `ex3` executes but after the symbol binding occurs on `ex3`.
2. You might have seen references to the `_mh_execute_header` symbol earlier when dumping the symbol table for an executable. This symbol is inserted by the compiler for executables (and not for dylibs). This can be used to get the start address of the main executable at runtime which is helpful due to the memory layout being slid around every time its launched. This is known as **ASLR** and is outside the scope of this tutorial, but interested readers can [google more info](https://www.google.com/search?q=pie+aslr).
3. Once the header to the main executable is resolved, the **`getsectiondata`** API is used to find the address to `__DATA_CONST.__got`. Since these addresses are bound at this time, one can simply walk the size of the section searching for references to `security_check`. A lengthier but more elegant solution would be to use the knowledge from above to grab the indirect and direct symbol table to find the exact address that's needed to be patched.
4. `__DATA_CONST` is read-only by the time this code has access to it so the memory protection needs to be modified. Apple has a powerful set of Mach `vm_*` APIs that can work across processes with what is known as a **task**. In order to get a handle for the task belonging to the current process, you can use the **`mach_task_self()`** API. Mach is a detailed and complex topic which is also outside the scope of this writeup.  
5. The new local overwritten function pointer to `my_security_check` is applied.
6. After the function pointer is patched, `__DATA_CONST` is made read only again.

Compiling `solution3.c` then running with the `dyld` binding flags environment variable produces the following:

```bash
~ xcrun -sdk macosx clang -arch arm64 solution3.c -O0 -shared -o /tmp/solution3.dylib -mmacosx-version-min=12.6 -Wl,-U,__mh_execute_header,-U,_security_check

~ DYLD_INSERT_LIBRARIES=/tmp/solution3.dylib DYLD_PRINT_BINDINGS=1 /tmp/ex3
dyld[46523]: <solution3.dylib/bind#0> -> 0x10064c000 (ex3/__mh_execute_header)
dyld[46523]: <solution3.dylib/bind#1> -> 0x18da74690 (libmacho.dylib/_getsectiondata)
dyld[46523]: <solution3.dylib/bind#2> -> 0x182f41208 (libsystem_kernel.dylib/_mach_error_string)
dyld[46523]: <solution3.dylib/bind#3> -> 0x1dbed5aec (libsystem_kernel.dylib/_mach_task_self_)
dyld[46523]: <solution3.dylib/bind#4> -> 0x182e68ee8 (libsystem_c.dylib/_printf)
dyld[46523]: <solution3.dylib/bind#5> -> 0x10064fe20 (ex3/_security_check)
dyld[46523]: <solution3.dylib/bind#6> -> 0x182f3f4f8 (libsystem_kernel.dylib/_vm_protect)
dyld[46523]: <solution3.dylib/bind#7> -> 0x182f65934 (libsystem_kernel.dylib/_vm_write)
dyld[46523]: fixup: *0x00010076C000 = 0x00010064C000
dyld[46523]: fixup: *0x00010076C008 = 0x00018DA74690
dyld[46523]: fixup: *0x00010076C010 = 0x000182F41208
dyld[46523]: fixup: *0x00010076C018 = 0x0001DBED5AEC
dyld[46523]: fixup: *0x00010076C020 = 0x000182E68EE8
dyld[46523]: fixup: *0x00010076C028 = 0x00010064FE20
dyld[46523]: fixup: *0x00010076C030 = 0x000182F3F4F8
dyld[46523]: fixup: *0x00010076C038 = 0x000182F65934
dyld[46523]: <ex3/bind#0> -> 0x18da961c4 (libcommonCrypto.dylib/_CC_MD5)
dyld[46523]: <ex3/bind#1> -> 0x182ea3ce8 (libsystem_c.dylib/___stack_chk_fail)
dyld[46523]: <ex3/bind#2> -> 0x1dbed5798 (libsystem_c.dylib/___stack_chk_guard)
dyld[46523]: <ex3/bind#3> -> 0x182f8ccb0 (libsystem_platform.dylib/__platform_memcmp)
dyld[46523]: <ex3/bind#4> -> 0x182e68ee8 (libsystem_c.dylib/_printf)
dyld[46523]: <ex3/bind#5> -> 0x182f8c860 (libsystem_platform.dylib/__platform_strlen)
dyld[46523]: fixup: *0x000100650000 = 0x00018DA961C4
dyld[46523]: fixup: *0x000100650008 = 0x000182EA3CE8
dyld[46523]: fixup: *0x000100650010 = 0x0001DBED5798
dyld[46523]: fixup: *0x000100650018 = 0x000182F8CCB0
dyld[46523]: fixup: *0x000100650020 = 0x000182E68EE8
dyld[46523]: fixup: *0x000100650028 = 0x00010064FE20
dyld[46523]: fixup: *0x000100650030 = 0x000182F8C860
start is 0x00010064c000, patching offset 0x000100650028
interposed security_check! returning match
🌈success!🌈
```

Excellent : ]

## Challenge 4: symbol hooking 

*Execute the `do_the_thing()` function through whatever means, but you're only allowed to modify executable memory in `ex4`.*

```c
// ex4.c 
// xcrun -sdk macosx clang -arch arm64 ex4.c -o /tmp/ex4 -O0 -mmacosx-version-min=12.6

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <CommonCrypto/CommonCrypto.h>

int security_check(const char *password) {
    char result[CC_MD5_DIGEST_LENGTH];
    if (!password) {
        return 0;
    }
    CC_MD5(password, strlen(password), (unsigned char *)result); 
    char secret[CC_MD5_DIGEST_LENGTH] = "\x5f\x4d\xcc\x3b\x5a\xa7\x65\xd6"
                                        "\x1d\x83\x27\xde\xb8\x82\xcf\x99";
    return memcmp(result, secret, CC_MD5_DIGEST_LENGTH) == 0;
}

__attribute__((always_inline)) // 1
static void do_the_thing(void) {
    printf("🌈success!🌈\n");
}

int main(int argc, const char* argv[]) {
    if (security_check(argc > 1 ? argv[1] : NULL)) { // 4
        do_the_thing();
    }
    return 0;
}
```

**Assessment** Things are getting more interesting. The `do_the_thing()` function is no longer a stand alone function, thanks to **`__attribute__((always_inline))`**. If you were to compile this and use `nm` you would not see a symbol for this function anymore. The contents of the `do_the_thing()` function will get compiled directly into the `main` function. 


For this challenge, a new restriction is added. Only executable memory can be modified. Fortunately, it is possible to hijack control through **symbol hooking**. You will augment executable memory to jump to a different location by patching executable memory at runtime. Since `security_check` is a public symbol and gates control to the newly inlined `do_the_thing()` function, patching `security_check` looks to be the ideal target. 

### Patching ARM64 Executable Memory

When patching executable memory, there are several ~~headaches~~ trade-offs one needs to consider. Jumping to an address that is farther away requires more assembly instructions. ARM64 operands are only 4 bytes in size, so a pointer of 8 bytes can't all fit into one instruction. As a result, branching to a function often occurs via a relative offset to the **program counter**. This means one must be conscious of the difference between the address to patch as well as the address that one wants to jump to. In addition, the size of the augmented function must be considered so as to not overwrite the contents of a different function.

> **NOTE** Patching executable memory only gets more complicated if one wants to call the original function inside of the patched function. Diverting control from the original function means there are assembly instructions that are no longer there due to the patch. In order to work around this, one either needs to temporarily repatch the original instructions, or patch the call sites to the original function, or attempt to replicate and execute the original patched instructions and jump to the offset immediately after the injected shellcode. Fortunately, this writeup steers clear of all those ideas preferring to entirely replace the original function.

For this solution, 3 ARM64 operands will be used and inserted into the beginning of `security_check` to divert control to a new function that always returns success. This will result in 12 bytes being replaced into the beginning of `security_check`. These instructions: are **ADRP**, **ADD**, & **BR**.

Breaking down the pseudocode for each of these instructions and what will happen:

* **`adrp x8, ((M(D) - M(S)) / 4096`** - Where S is the start address (address of `security_check`), D is the destination address (address of the soon to be created patched function called `my_security_check`) and `M()` ensures the address is aligned to 4KB. This value is then divided by 4KB to figure out the offset to jump to from the current program counter (pc). This gives a +-4GB offset from the program counter to jump to and will store the value into the `x8` register. An assumption is made that the solution's executable memory will be within this range. If this does not hold true, more assembly instructions would be needed to load an absolute address by OR'ing in different parts of the address and storing it in the same register.
* **`add x8, x8, (D & 0xFFF)`** - The `adrp` instruction will get the program counter within a 4KB range of where to execute. The final value that is needed can be set to a register via the `add` instruction.
* **`br x8`** - Once the `x8` register contains the appropriate address, branch to the address.

Here's the source code to generate the shellcode and patch the `security_check` function before it executes:


```c
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
```

Ouch. That's a lot of code, but the majority of it is to generate the assembly instructions to patch the `security_check` which will not be discussed in depth. Breaking down the interesting points:

1. The `CREATE_ADRP_OP` function will create an ARM64 instruction that will calculate the floor of the 4KB memory aligned address it needs to jump to relative to the current address it is patching.
2. The `CREATE_ADD_OP` will get the register to the final offset relative to the 4KB memory alignment address currently stored into the register. In this case, it will set register x8 to the value of `my_security_check`.
3. The `adrp` + `add` + `br` set of instructions are assembled together and made into shellcode. The `br x8` instruction will branch to that location without linking to a return address giving it illusion that the hooking function was called directly.
4. This attempts to change the executable memory into temporarily writable memory. This code differs from the previous solution in that if the write permissions fail, the code will try to create a copy of the memory that is writeable.
5. The shellcode is written to the beginning of the `security_check` method. It is assumed that the `security_check` function is longer than 3 assembly instructions (12 bytes). Ideally, there should be code to check the size of this function, which can be determined through the `LC_FUNCTION_STARTS` load command.

With everything compiled and giving it a run:

```bash
~ xcrun -sdk macosx clang -arch arm64 solution4.c -O0 -shared -o /tmp/solution4.dylib -mmacosx-version-min=12.6 -Wl,-U,_security_check

~ DYLD_INSERT_LIBRARIES=/tmp/solution4.dylib /tmp/ex4
attempting to patch security_check @ 0x000100e6be18 with my_security_check 0x00010103f9e0
interposed security_check! returning success
🌈success!🌈
```

## Challenge 5: real world

*Execute the `do_the_thing()` logic through whatever means, but you may not modify executable memory nor may you interpose undefined symbols. In addition, `ex5` must also exit successfully.*

```c
// ex5.c 
// xcrun -sdk macosx clang -arch arm64 ex5.c -o /tmp/ex5 -O3  -mmacosx-version-min=12.6 -Wl,-no_function_starts -fstack-protector-all && strip ex5 #2

#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <stdio.h>
#include <CommonCrypto/CommonCrypto.h>

__attribute__((always_inline)) // 1
int security_check(const char *password) {
    char result[CC_MD5_DIGEST_LENGTH];
    if (!password) {
        return 0;
    }
    CC_MD5(password, strlen(password), (unsigned char *)result); 
    char secret[CC_MD5_DIGEST_LENGTH] = "\x5f\x4d\xcc\x3b\x5a\xa7\x65\xd6"
                                        "\x1d\x83\x27\xde\xb8\x82\xcf\x99";
    return memcmp(result, secret, CC_MD5_DIGEST_LENGTH) == 0;
}

__attribute__((always_inline)) // 1
static void do_the_thing(void) {
    printf("🌈success!🌈\n");
}

int main(int argc, const char* argv[]) {
    if (security_check(argc > 1 ? argv[1] : NULL)) { // 4
        do_the_thing();
    }
    return 0;
}
```

**Assessment** It's getting trickier. `security_check` is no longer a standalone function thanks to the `always_inline` attribute (#1). In addition, new compilation flags have been added. They include: 
* All function names are removed thanks to the `strip` command.
* The `-Wl,-no_function_starts` instructs the linker to not embed the **LC_FUNCTION_STARTS** Mach-O load command in the resolved binary. This load command lists the start (and thereby the size) of every compiled function found in `ex5`. Without this load command, it becomes significantly trickier to determine where functions begin and end.
* `-fstack-protector-all` inserts stack protection logic at the beginning and end of callsites within `ex5`. This makes jumping to offsets within functions trickier.

It's best to see what is under the hood. Compile and dump the assembly for `ex5`:
```asm
~ xcrun -sdk macosx clang -arch arm64 ex5.c -o /tmp/ex5 -O3  -mmacosx-version-min=12.6 -Wno-deprecated-declarations -Wl,-no_function_starts -fstack-protector-all && strip ex5
~ otool -tV /tmp/ex5
ex5:
(__TEXT,__text) section
3 ->    0000000100003ea8     sub     sp, sp, #0x40
        0000000100003eac     stp     x20, x19, [sp, #0x20]
        0000000100003eb0     stp     x29, x30, [sp, #0x30]
        0000000100003eb4     add     x29, sp, #0x30
        0000000100003eb8     nop
        0000000100003ebc     ldr     x8, #0x154 ; literal pool symbol address: ___stack_chk_guard
        0000000100003ec0     ldr     x8, [x8]
        0000000100003ec4     str     x8, [sp, #0x18]
        0000000100003ec8     cmp     w0, #0x1
        0000000100003ecc     b.le     0x100003f30
        0000000100003ed0     ldr     x19, [x1, #0x8]
        0000000100003ed4     cbz     x19, 0x100003f30
        0000000100003ed8     mov     x0, x19
1 ->    0000000100003edc     bl     0x100003f84 ; symbol stub for: _strlen
        0000000100003ee0     mov     x1, x0
        0000000100003ee4     add     x2, sp, #0x8
        0000000100003ee8     mov     x0, x19
1 ->    0000000100003eec     bl     0x100003f60 ; symbol stub for: _CC_MD5
        0000000100003ef0     mov     x8, #0x4d5f
        0000000100003ef4     movk     x8, #0x3bcc, lsl #16
        0000000100003ef8     movk     x8, #0xa75a, lsl #32
        0000000100003efc     movk     x8, #0xd665, lsl #48
        0000000100003f00     ldp     x9, x10, [sp, #0x8]
        0000000100003f04     eor     x8, x9, x8
        0000000100003f08     mov     x9, #0x831d
        0000000100003f0c     movk     x9, #0xde27, lsl #16
        0000000100003f10     movk     x9, #0x82b8, lsl #32
        0000000100003f14     movk     x9, #0x99cf, lsl #48
        0000000100003f18     eor     x9, x10, x9
        0000000100003f1c     orr     x8, x8, x9
2 ->    0000000100003f20     cbnz     x8, 0x100003f30
        0000000100003f24     adr     x0, #0x7c ; literal pool for: "\360\237\214\210success!\360\237\214\210"
        0000000100003f28     nop
        0000000100003f2c     bl     0x100003f78 ; symbol stub for: _puts
3 ->    0000000100003f30     ldr     x8, [sp, #0x18]
        0000000100003f34     nop
        0000000100003f38     ldr     x9, #0xd8 ; literal pool symbol address: ___stack_chk_guard
        0000000100003f3c     ldr     x9, [x9]
        0000000100003f40     cmp     x9, x8
        0000000100003f44     b.ne     0x100003f5c
        0000000100003f48     mov     w0, #0x0
        0000000100003f4c     ldp     x29, x30, [sp, #0x30]
        0000000100003f50     ldp     x20, x19, [sp, #0x20]
        0000000100003f54     add     sp, sp, #0x40
        0000000100003f58     ret
        0000000100003f5c     bl     0x100003f6c ; symbol stub for: ___stack_chk_fail
```

From the above assembly and the given challenges of returning without error and being unable to interpose symbols nor modify executable memory, three ideas stand out which are highlighted with arrows.

1. Put a **hardware breakpoint** (which doesn't modify executable memory) on `strlen` or `CC_MD5` and have a debugger catch either function. Once caught, modify the return address via settings the **lr** register to get past the checks. For this case, address `0x0000000100003f24` looks like a good candidate to return to as it sidesteps all of the conditional checks. One must ensure that the caller is coming from `ex5`, which can be done via a `__builtin_return_address(0)`.
2. Put a hardware breakpoint at the start of `main` and have a debugger step through each assembly instruction as they occur while the debugger catches and processes each opcode. At address `0x0000000100003f20`, there's the `cbnz     x8, 0x100003f30` opcode instruction which branches past executing `do_the_thing()` when the register is non-zero. When the debugger sees the `cbnz` instruction occur, have the debugger modify the register before the assembly instruction occurs resulting in the conditional check succeeding.
3. Put a hardware breakpoint at the start of the `main` function and have a debugger directly set execution control to `0x0000000100003f24`. Put another hardware breakpoint on address `0x0000000100003f30` and then set the program counter to `0x0000000100003f48`, which contains the logic to return gracefully from `main`. This essentially let's the program jump to the relevant code while sidestepping the security checks.

Although it's far from the most efficient solution for code length, idea 2 seems the most interesting to implement. The following code is broken into 2 snippets given the length of code needed to create an process debugger that steps through and processes assembly instructions.

First the logic is setup a `dylib` that's a debugger in order to catch breakpoints:

```c
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

// continued...
```
Breaking down the interesting points:
1. When creating a "debugger" for Apple OS's, **mach messages** are used so the kernel can talk to the debugger which replies on how it wants to handle these messages. This can be any process and can even live in the same process, which is the case here. This communication mechanism is typically generated over the Mach Interface Generator or simply, **mig**, which generates the structs to send and receive information. The file responsible for this is **`<mach/mach_exc.defs>`**. Typically a developer will use the `mig` tool to generate the interface protocol and include the files needed to communicate. In order to keep the code as small as possible, the interface is extracted out and directly compiled into the solution. For interested readers, see `cp $(xcrun --show-sdk-path)/usr/include/mach/mach_exc.defs /tmp/ && mig /tmp/mach_exc.defs && cat /tmp/mach_exc.h`
2. A struct which determines if an ARM64 `cbnz` opcode is declared. This will be used when reading values off the program counter as the debugger is single stepping through instructions.
3. Since the symbol names were stripped out, there needs to be logic to find the address of `main`. This is accomplished with the `LC_MAIN` load command found at the beginning of all executables (and not dylibs). This will be used to create the software breakpoint.
4. A mach port is created and set to be the receiver for "breakpoint exceptions". This is the basis for handling exception logic and is a complex topic outside the scope of this writeup. Interested consumers can be notified of a variety of exceptions but only **EXC_MASK_BREAKPOINT** is used. Check out **`<mach/exception_types.h>`** for more options that can be caught.
5. The port to catch a software/hardware breakpoint is setup. The hardware breakpoint is set to the start of `main` via the **`thread_set_state`** API.
6. After everything is setup, a new thread is spun up to handle all debugging communication with the kernel. This new thread will call into **`void* server_thread(void *arg) `** which will be shown in the next code snippet.

The logic for the debugger is setup, now the **`server_thread`** will facilitate how the debugger interacts interacts with the kernel and `ex5`:

```c
// continued... 

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
```

Here's the interesting points in `server_thread`:

1. For processing assembly opcodes, there's only interest in looking in opcodes found in `ex5`.This logic finds the `ex5`'s upper and lower bounds for executable memory. Later on, the program counter will be extracted out and compared against these bounds.
2. This is part of the boiler plate logic that was done in the `mig` `mach_exc.defs` generated file. Once the payload is setup, it polls waiting for an "event", which will be the breakpoint on `main`. When the breakpoint trips, control will send a message out to the debugger and execution will resume past `mach_msg_receive` while the kernel waits for a response on how to handle the frozen thread, thanks to the hardware breakpoint on `main`.
3. The `arm_thread_state64_t` will contain all the values for registers, including the link register and the program counter, which can be modified using the `thread_set_state` API.
4. An interesting component to working with ARM64e CPUs is that the program counter could have pointer authentication for ARM64e CPU slices. This value needs to be removed so a bogus program counter is not interpreted.
5. The `arm_debug_state64_t` is another awesome struct for the `thread_(get|set)_state` API. As you saw earlier this can set software breakpoints, watchpoints or even do instruction stepping. The line of code to instruction step is `dbg.__mdscr_el1 |= SS_ENABLE`. This will result in instruction step immediately following a call back into the debugger as it raises a breakpoint exception.
6. The opcode is read from the current program counter. If the opcode is a `cbnz`, then the register is set to the opposite value and saved.
7. This logic is to reply to the kernel saying that this exception has be handled (thanks to `resp->RetCode = KERN_SUCCESS`) and it is OK for the program to resume execution.

Putting the code together and running:

```bash
~ xcrun -sdk macosx clang -arch arm64 solution5.c -O0 -shared -o /tmp/solution5.dylib -mmacosx-version-min=12.6 -Wl,-U,__mh_execute_header
~ DYLD_INSERT_LIBRARIES=/tmp/solution5.dylib /tmp/ex5 boom
Exception port setup with port 2563
Breakpoint set on main 0x000100e7fea8 (offset 0x003ea8)
exception server starting
Patching register x8 at address 0x000100e7ff20 (offset 0x003f20)
🌈success!🌈
```

## epilogue

As you have seen, there are many ways to go about altering execution of code. Hopefully this was insightful and you have a better understanding of the different strategies that are available.

Have fun jumping around 🍻

