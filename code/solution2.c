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
