/*
  Goal:
   1. See how Windows tracks loaded modules in real time
   2. Validate everything you already learned about PEB,
   loader lists, DLL order
  
 */

#include <stdio.h>
#include <windows.h>
#include <winnt.h>

#ifdef _M_X64
#define GET_PEB() ((PEB*)__readgsqword(0x60))
#else
#define GET_PEB() ((PEB*)__readfsdword(0x30))
#endif

#define RVA_TO_VA(base, rva) ((void *)((BYTE*)(base) + (rva)))

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

//Relocation dump function
void DumpRelocations(void *moduleBase){
    //What this line represent?
    /* This points to the very first bytes of the PE image in memory.
       Every PE starts with: MZ (That's the DOS header).
       Why do we care?
       Because DOS header contains: dos->e_lfanew
       Which means: "Offset to the real PE header"
       Think of it like: "DOS stub -> PE header pointer"
     */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)moduleBase;

    //What this line represent?
    /* (BYTE *)moduleBase => treat base  as raw byte
        + dos->e_lfanew   => jump to where PE header starts
        cast to IMAGE_NT_HEADERS64 => now we can read PE metadata
        This structure contains:
         1. OptionalHeader, 2. DataDirectory, 3. ImageBase, 4. Section layout
         This is where relocations are described.
    */
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((BYTE *)moduleBase + dos->e_lfanew);

    //this is where relocation live
    IMAGE_DATA_DIRECTORY *relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if(!relocDir->VirtualAddress || !relocDir->Size){
        printf("No relocation table\n");
        return;
    }

    //We get virtual address  with modulebase and relocationDir virtaul Address
    BYTE *relocBase = RVA_TO_VA(moduleBase, relocDir->VirtualAddress);

    //relocationEND =  RVA + relocationDir size
    BYTE *relocEnd = relocBase + relocDir->Size;

    printf("\n Base Relocations: \n");
    while(relocBase < relocEnd){
        //Each block means: "fixups for one 4KB page"
        IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)relocBase;
        
        //Number of entries
        DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        WORD *entries = (WORD *)(block + 1);

        for(DWORD i = 0; i < count; i++){
            
            WORD type = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;

            if(type == IMAGE_REL_BASED_DIR64){
                //Relocation entry = (Actual mapped Base + PageRVA + Offset inside page)
                void *fixup = (BYTE *)moduleBase + block->VirtualAddress + offset;
                printf("Fixup @ %p\n", fixup);
            }
        }
        relocBase += block->SizeOfBlock;
    }
}

void DumpEAT(void *moduleBase){
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)moduleBase;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((BYTE *)moduleBase + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if(!expDir->VirtualAddress){
        printf("No exports\n");
        return;
    }

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)moduleBase + expDir->VirtualAddress);

    DWORD *funcRVAs = (DWORD *)((BYTE *)moduleBase + exp->AddressOfFunctions);
    DWORD *namesRVAs = (DWORD *)((BYTE *)moduleBase + exp->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)moduleBase + exp->AddressOfNameOrdinals);

    printf("\n\n[EAT] Exports: \n");
    for(DWORD i = 0; i < exp->NumberOfNames; i++){
        char *name = (char *)moduleBase + namesRVAs[i];
        WORD ordIndex = ordinals[i];
        void *funcAddr = (BYTE *)moduleBase + funcRVAs[ordIndex];

        printf("  %s -> %p\n", name, funcAddr);
    }
}

BOOL IsAddressInKnownModule(void *addr){
    PEB *peb = GET_PEB();
    M_LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    M_LIST_ENTRY *e = head->Flink;
    LIST_FOR_EACH(e, head){
        LDR_DATA_TABLE_ENTRY *mod =
            CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLink);

        BYTE *start = (BYTE *)mod->DllBase;
        BYTE *end   = start + mod->SizeOfImage;

        if ((BYTE *)addr >= start && (BYTE *)addr < end)
            return TRUE;
    }
    return FALSE;
}
C
void DumpIAT(void *moduleBase){
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)moduleBase;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)((BYTE *)moduleBase + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY *impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if(!impDir->VirtualAddress){
        printf("No imports\n");
        return;
    }

    //Import Table
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)moduleBase + impDir->VirtualAddress);
    printf("\n\n[IAT] Imports:\n");

    //Walking import descriptors 
    for(; desc->Name; desc++){
        char *dllName = (char *)moduleBase + desc->Name;
        printf("\nDLL: %s\n", dllName);

        
        //OriginalFirstThunk = Import Lookup Table (ILT), [Exist on disk]
        IMAGE_THUNK_DATA64 *origThunk = (IMAGE_THUNK_DATA64 *)((BYTE *)moduleBase + desc->OriginalFirstThunk);

        //FirstThunk = Import Address Table (IAT), [Exist in memory]
        IMAGE_THUNK_DATA64 *iatThunk = (IMAGE_THUNK_DATA64 *)((BYTE *)moduleBase + desc->FirstThunk);

        //walking function by function
        for(; origThunk->u1.AddressOfData; origThunk++, iatThunk++){
            if(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64){
                //Imported by Ordinal
                printf("  Oridnal -> %p\n", (void *)iatThunk->u1.Function);
                continue;
            }

            IMAGE_IMPORT_BY_NAME *name = (IMAGE_IMPORT_BY_NAME *)((BYTE *)moduleBase + origThunk->u1.AddressOfData);

            void *resolved = (void *)iatThunk->u1.Function;
            printf("  %s  -> %p", name->Name, resolved);

            // Hook detection
            if(!IsAddressInKnownModule(resolved)){
                printf(" [HOOKED] ");
            }
         
            printf("\n");
        }
    }
}

int main(){
    //LoadLibraryA("user32.dll");
    PEB *peb = GET_PEB();
    PEB_LDR_DATA *ldr = peb->Ldr;

    M_LIST_ENTRY *mHead = &ldr->InLoadOrderModuleList;
    M_LIST_ENTRY *mCurr = mHead->Flink;
    M_LIST_ENTRY *memHead = &ldr->InMemoryOrderModuleList;
    M_LIST_ENTRY *memCurr = memHead->Flink;
    
    printf("Loaded Modules (LOAD Order):\n Who Entered the process, and when?\n");
    LIST_FOR_EACH(mCurr, mHead){
        LDR_DATA_TABLE_ENTRY *entry =
            container_of(mCurr, LDR_DATA_TABLE_ENTRY, InLoadOrderLink);

        if(wcscmp(entry->BaseDllName.Buffer, L"mLI.exe") == 0){
            DumpRelocations(entry->DllBase);
            DumpEAT(entry->DllBase);
        }
         if(wcscmp(entry->BaseDllName.Buffer, L"KERNEL32.DLL") == 0){
            DumpEAT(entry->DllBase);
            DumpIAT(entry->DllBase);
        }
        
        wprintf(L"Base: %p Name: %ls SizeOfImage: %lu\n",
                entry->DllBase,
                entry->BaseDllName.Buffer,
                entry->SizeOfImage);
    }

    printf("\n\nMemory Modules (Memory Order):\n Who lives where in VA space?\n");
    LIST_FOR_EACH(memCurr, memHead){
        LDR_DATA_TABLE_ENTRY *entry =
            container_of(memCurr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLink);
        wprintf(L"Memory Base: %p Name: %ls SizeOfImage: %lu\n",
                entry->DllBase,
                entry->BaseDllName.Buffer,
                entry->SizeOfImage);
    }

    printf("\n\nInitialization Modules (Initialization Order):\n Who was ready before whom?\n");
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
