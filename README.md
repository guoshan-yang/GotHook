# Got表之导入表hook
这里我们通过program header table，先找到`.dynamic`段，也是动态链接中最重要的结构段，保存了动态链接器所需要的基本信息，比如依赖哪些共享对象，动态链接符号表，重定位表等。然后在`.dynamic`段遍历找到，动态符号表，字符串表以及重定位表，下面来看一下具体代码和段结构: 

代码量很少，几乎每行代码都有注释。

先获取到so文件加载到内存的基地址，可以通过/proc/[pid]/maps 获取到的。

```
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
```

解析文件头Elf32_Ehdr结构: 

```c
long base_addr = get_module_base(getpid(), LIB_NAME);
// 备份原地址
old_malloc = malloc;
/*
typedef struct
{
  unsigned char	e_ident[16];	/* Magic number and other info */
  Elf32_Half	e_type;			/* Object file type */
  Elf32_Half	e_machine;		/* Architecture */
  Elf32_Word	e_version;		/* Object file version */
  Elf32_Addr	e_entry;		/* Entry point virtual address */
  Elf32_Off	e_phoff;		/* Program header table file offset */
  Elf32_Off	e_shoff;		/* Section header table file offset */
  Elf32_Word	e_flags;		/* Processor-specific flags */
  Elf32_Half	e_ehsize;		/* ELF header size in bytes */
  Elf32_Half	e_phentsize;		/* Program header table entry size */
  Elf32_Half	e_phnum;		/* Program header table entry count */
  Elf32_Half	e_shentsize;		/* Section header table entry size */
  Elf32_Half	e_shnum;		/* Section header table entry count */
  Elf32_Half	e_shstrndx;		/* Section header string table index */
} Elf32_Ehdr;
*/

Elf32_Ehdr *elf32_ehdr = (Elf32_Ehdr*)base_addr;


/*
找到.dynamic段，结构如下:
typedef struct
{
  Elf32_Sword	d_tag;			/* Dynamic entry type */
  union
    {
      Elf32_Word d_val;			/* Integer value */
      Elf32_Addr d_ptr;			/* Address value */
    } d_un;
} Elf32_Dyn;
*/
for (int j = 0; j < elf32_ehdr->e_phnum; j++){
    if (elf32_phdr[j].p_type == PT_DYNAMIC){
        dynamicAddr = static_cast<long>(elf32_phdr[j].p_vaddr + base_addr);
        dynamicSize = elf32_phdr[j].p_memsz;
        break;
    }
}


// 遍历dynamic段找到，动态符号表，字符串表以及重定位表等
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
```
