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
