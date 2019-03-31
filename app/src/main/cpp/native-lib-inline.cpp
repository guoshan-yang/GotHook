#include <jni.h>
#include <string>
#include <android/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,"Xlog",__VA_ARGS__)


#include "include/inlineHook.h"
FILE* (*old_fopen)(const char*, const char*) = NULL;
FILE* new_fopen(const char* __path, const char* __mode) {
    LOGD("path = %s",__path);
    return old_fopen(__path,__mode);
}

int hook() {
    if (registerInlineHook((uint32_t) fopen, (uint32_t) new_fopen, (uint32_t **) &old_fopen) != ELE7EN_OK) {
        LOGD("registerInlineHook err");
        return -1;
    }
    if (inlineHook((uint32_t) fopen) != ELE7EN_OK) {
        LOGD("inlineHook err");
        return -1;
    }
    LOGD("hook ok");
    return 0;
}
int unHook() {
    if (inlineUnHook((uint32_t) fopen) != ELE7EN_OK) {
        return -1;
    }

    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_iwcode_gothook_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

void __attribute__((constructor)) init_func()
{
    int s = hook();
    LOGD("hook result = %d",s);
    fopen("/sdcar/a.apk","r");
//    unHook();
}


void __attribute__((destructor)) des_func(){
    LOGD("des_func");
}
