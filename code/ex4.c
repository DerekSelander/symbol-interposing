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
