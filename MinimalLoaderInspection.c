/*
  Goal:
   1. See how Windows tracks loaded modules in real time
   2. Validate everything you already learned about PEB,
   loader lists, DLL order
  
 */

#include <stdio.h>
#include <windows.h>

#ifdef _M_X64
#define GET_PEB() ((PEB*)__readgsqword(0x60))
#else
#define GET_PEB() ((PEB*)__readfsdword(0x30))
#endif

#define field_offset(type, field) \
    ((size_t)&(((type *)0)->field))

#define container_of(ptr, type, member) \
    ((type *)((char *)(ptr) - field_offset(type, member)))

#define LIST_FOR_EACH(pos, head) \
    for(pos = (head)->Flink; pos != (head); pos = pos->Flink)

//user-Defined  DATA_TYPE
typedef struct _UNICODE_STRING{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

//Intrusive Link struct
//[access by LDR_DATA_TABLE_ENTRY ->ListEntry Linker members]
typedef struct MY_LIST_ENTRY{
    struct MY_LIST_ENTRY *Flink;
    struct MY_LIST_ENTRY *Blink;
} M_LIST_ENTRY;

//Object (intrusive list struct)
//[Access by PEB_LDR_DATA ->listEntry member]
typedef struct MY_LDR_DATA_TABLE_ENTRY{
    M_LIST_ENTRY InLoadOrderLink;
    M_LIST_ENTRY InMemoryOrderLink;
    M_LIST_ENTRY InInitializationOrderLinks;
    void *DllBase;
    void *EntryBase;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

//[Access by PEB struct]
typedef struct MY_PEB_LDR_DATA{
    ULONG Length;
    BOOLEAN Initialized;
    void *SsHandle;
    M_LIST_ENTRY InLoadOrderModuleList; //Intrusive list link head
    M_LIST_ENTRY InMemoryOrderModuleList;
    M_LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct PEB{
    BYTE reserved1[0x18];
    PEB_LDR_DATA *Ldr; //this gives loader info
} PEB;


int main(){

    PEB *peb = GET_PEB();
    PEB_LDR_DATA *ldr = peb->Ldr;

    M_LIST_ENTRY *mHead = &ldr->InLoadOrderModuleList;
    M_LIST_ENTRY *mCurr = mHead->Flink;
    M_LIST_ENTRY *memHead = &ldr->InMemoryOrderModuleList;
    M_LIST_ENTRY *memCurr = memHead->Flink;
    
    printf("Loaded Modules (LOAD Order):\n\
Who Entered the process, and when?\n");
    LIST_FOR_EACH(mCurr, mHead){
        LDR_DATA_TABLE_ENTRY *entry =
            container_of(mCurr, LDR_DATA_TABLE_ENTRY, InLoadOrderLink); 
        wprintf(L"Base: %p Name: %ls SizeOfImage: %lu\n",
                entry->DllBase,
                entry->BaseDllName.Buffer,
                entry->SizeOfImage);
    }

    printf("\n\nMemory Modules (Memory Order):\n\
Who lives where in VA space?\n");
    LIST_FOR_EACH(memCurr, memHead){
        LDR_DATA_TABLE_ENTRY *entry =
            container_of(memCurr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLink);
        wprintf(L"Memory Base: %p Name: %ls SizeOfImage: %lu\n",
                entry->DllBase,
                entry->BaseDllName.Buffer,
                entry->SizeOfImage);
    }

    printf("\n\nInitialization Modules (Initialization Order):\n\
Who was ready before whom?\n");
    M_LIST_ENTRY *iHead = &ldr->InInitializationOrderModuleList;
    M_LIST_ENTRY *curr = mHead->Flink;
    LIST_FOR_EACH(curr, iHead){
        LDR_DATA_TABLE_ENTRY *e =
            container_of(curr, LDR_DATA_TABLE_ENTRY,
                         InInitializationOrderLinks);
        wprintf(L"Memory Base: %p Name: %ls  SizeOfImage: %lu\n",
                e->DllBase,
                e->BaseDllName.Buffer,
                e->SizeOfImage);
    }


    getchar();
    return 0;
}

/*Output:
Loaded Modules (LOAD Order):
Who Entered the process, and when?
Base: 00007ff6776d0000 Name: mLI.exe SizeOfImage: 266240
Base: 00007ffce6f60000 Name: ntdll.dll SizeOfImage: 2519040
Base: 00007ffce69e0000 Name: KERNEL32.DLL SizeOfImage: 823296
Base: 00007ffce42e0000 Name: KERNELBASE.dll SizeOfImage: 4124672
Base: 00007ffce6c80000 Name: msvcrt.dll SizeOfImage: 692224


Memory Modules (Memory Order):
Who lives where in VA space?
Memory Base: 00007ff6776d0000 Name: mLI.exe SizeOfImage: 266240
Memory Base: 00007ffce6f60000 Name: ntdll.dll SizeOfImage: 2519040
Memory Base: 00007ffce69e0000 Name: KERNEL32.DLL SizeOfImage: 823296
Memory Base: 00007ffce42e0000 Name: KERNELBASE.dll SizeOfImage: 4124672
Memory Base: 00007ffce6c80000 Name: msvcrt.dll SizeOfImage: 692224


Initialization Modules (Initialization Order):
Who was ready before whom?
Memory Base: 00007ffce6f60000 Name: ntdll.dll  SizeOfImage: 2519040
Memory Base: 00007ffce42e0000 Name: KERNELBASE.dll  SizeOfImage: 4124672
Memory Base: 00007ffce69e0000 Name: KERNEL32.DLL  SizeOfImage: 823296
Memory Base: 00007ffce6c80000 Name: msvcrt.dll  SizeOfImage: 692224

 */
