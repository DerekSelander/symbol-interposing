// solution1.c
// xcrun -sdk macosx clang -arch arm64 solution1.c -O0 -shared -o /tmp/solution1.dylib -Wl,-U,_do_the_thing  -mmacosx-version-min=12.6 # 1
__attribute__((destructor)) void deinit(void) { // 2
    extern void do_the_thing(void); // 3
    do_the_thing();
}
