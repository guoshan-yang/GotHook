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

extern "C" JNIEXPORT jstring JNICALL
Java_com_iwcode_gothook_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

#define LIB_NAME "libnative-lib.so"

void* (*old_malloc)(size_t __byte_count);
void* new_malloc(size_t __byte_count){
    LOGD("[+] New call fopen.%d\n",__byte_count);
    return old_malloc(__byte_count);
}

long get_module_base(pid_t pid, const char* module_name){
    FILE* fp;
    unsigned long addr = 0;
    char* pch;
    char filename[32];
    char line[1024];

    // 格式化字符串得到 "/proc/pid/maps"
    if(pid < 0){
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    }else{
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    // 打开文件/proc/pid/maps，获取指定pid进程加载的内存模块信息
    fp = fopen(filename, "r");
    if(fp != NULL){
        // 每次一行，读取文件 /proc/pid/maps中内容
        while(fgets(line, sizeof(line), fp)){
            // 查找指定的so模块
            if(strstr(line, module_name)){
                // 分割字符串
                pch = strtok(line, "-");
                // 16进制字符串转十进制整数,
                addr = strtoul(pch, NULL, 16);
                // 特殊内存地址的处理
                if(addr == 0x8000){
                    addr = 0;
                }
                break;
            }
        }
    }
    fclose(fp);
    return addr;
}

int hook_malloc(){
    long base_addr = get_module_base(getpid(), LIB_NAME);
    LOGD("base_addr = %p",(void*)base_addr);
    old_malloc = malloc;

    Elf32_Ehdr *elf32_ehdr = (Elf32_Ehdr*)base_addr;

    // program header table文件偏移
    Elf32_Phdr *elf32_phdr = (Elf32_Phdr*)(base_addr + elf32_ehdr->e_phoff);
    int phdr_count = elf32_ehdr->e_phnum;

    LOGD("phdr_count = %d",phdr_count);

    long dynamicAddr = 0;
    int dynamicSize = 0;
    for (int j = 0; j < phdr_count; j++){
        if (elf32_phdr[j].p_type == PT_DYNAMIC){
            dynamicAddr = static_cast<long>(elf32_phdr[j].p_vaddr + base_addr);
            dynamicSize = elf32_phdr[j].p_memsz;
            break;
        }
    }
    LOGD("Dynamic Addr : %p",(void*)dynamicAddr);
    LOGD("Dynamic Size : %d",dynamicSize);
    LOGD("Elf32_Dyn Size : %d", sizeof(Elf32_Dyn));

    Elf32_Dyn* dynamic_table = (Elf32_Dyn*)(dynamicAddr);
    int jmpRelOff = 0;
    int strTabOff = 0;
    int pltRelSz = 0;
    int symTabOff = 0;
    for(int i=0;i < dynamicSize / 8;i ++){
        int val = dynamic_table[i].d_un.d_val;
        // 重定位表
        if (dynamic_table[i].d_tag == DT_JMPREL){
            jmpRelOff = val;
        }
        // 字符串表
        if (dynamic_table[i].d_tag == DT_STRTAB)
        {
            strTabOff = val;
        }
        // 重定位表大小
        if (dynamic_table[i].d_tag == DT_PLTRELSZ)
        {
            pltRelSz = val;
        }
        // 符号表
        if (dynamic_table[i].d_tag == DT_SYMTAB)
        {
            symTabOff = val;
        }
    }
    Elf32_Rel* rel_table = (Elf32_Rel*)(jmpRelOff + (long long)base_addr);
    LOGD("jmpRelOff : %d",jmpRelOff);
    LOGD("strTabOff : %d",strTabOff);
    LOGD("symTabOff : %d",symTabOff);

    //  遍历重定位表
    for (int i = 0; i < pltRelSz / 8; ++i) {
        // 高24位表示重定位入口符号在符号表中的下标
        int number = rel_table[i].r_info >> 8;
        Elf32_Sym* symTableIndex = (Elf32_Sym*)(symTabOff + base_addr + number*16);
        // 获取符号对应的字符串
        char* funcName = (char*)(symTableIndex->st_name + strTabOff + base_addr);

        // 判断是否hook的函数
        if(strcmp(funcName,"malloc") == 0){
            // 获取页大小，一般默认都是4096
            int pagesize = getpagesize();
            // 获取内存分页的起始地址
            uint32_t mem_page_start = (uint32_t)(((Elf32_Addr)rel_table[i].r_offset + base_addr)) & (~(pagesize - 1));
            // 修改页属性
            mprotect(reinterpret_cast<void *>((uint32_t)mem_page_start), pagesize, PROT_READ | PROT_WRITE | PROT_EXEC);
            // hook函数
            *(unsigned int*)(rel_table[i].r_offset + base_addr) = reinterpret_cast<unsigned int>(new_malloc);
            // 还原页属性
            mprotect(reinterpret_cast<void *>((uint32_t)mem_page_start), pagesize, PROT_READ | PROT_EXEC);
        }
    }

    return 0;
}

void __attribute__((constructor)) init_func()
{
    hook_malloc();
    malloc(4);
}


void __attribute__((destructor)) des_func(){
    LOGD("des_func");
}
