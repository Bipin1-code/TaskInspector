/*
  Date: 20-Jan-2026
  Task Manager recreation with NT APIs

  structure form my winternl.h check your you may have WaitTime member inside STI struct
    typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER Reserved1[3];
    ULONG Reserved2;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG Reserved3;
    ULONG ThreadState;
    ULONG WaitReason;
  } SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;
But in NtQueryInformationThread has member call ThreadInformationClass ->ThreadTImes

  typedef struct _SYSTEM_THREADS 
  {
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
  ULONG ContextSwitchCount;
  THREAD_STATE State;
  KWAIT_REASON WaitReason;
  } SYSTEM_THREADS, *PSYSTEM_THREADS;
  
 */

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

extern NTSTATUS NTAPI NtOpenProcess(
                                    PHANDLE ProcessHandle,
                                    ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes,
                                    PCLIENT_ID ClientId
                                    );


void callNtQueryInformationProcess(HANDLE hProcess, PROCESSINFOCLASS ProcessInformationClass){
    PROCESS_BASIC_INFORMATION pbi; //intentionally not using EX version

    ULONG retLen = 0;
    NTSTATUS status = NtQueryInformationProcess(hProcess,
                                                ProcessInformationClass,
                                                &pbi,
                                                sizeof(pbi),
                                                &retLen);
    if(NT_SUCCESS(status)){
        wprintf(L" \x1b[32mParent PID:\x1b[0m %lu ",
                (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId);
        wprintf(L" \x1b[36mExitStatus:\x1b[0m %ls ",
                ((pbi.ExitStatus == 0x00000103) ? L"Running..." : L"Exited"));
        wprintf(L" \x1b[35mPEB:\x1b[0m %p ", pbi.PebBaseAddress);
    }else{
        wprintf(L" \x1b[31m NtQueryInformationProcess Failed: \x1b[0m 0x%08lx ",
                status);
    }
}

const char* printThreadState(ULONG state){
    static const char* states[] = {
        "Initialized", "Ready", "Running", "Standby",
        "Terminated", "Waiting", "Transition", "DeferredReady",
    };

    if(state <= 7){
        return states[state];
    }
    
    return "Unknown";
}

void printWaitReason(ULONG waitRNum){
    const char* waitReason[] = {
        "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution",
        "Suspended", "UserRequest", "WrExecutive", "WrFreePage", "WrPageIn",
        "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest",
        "WrEventPair", "WrQueue", "WrLpcReceive","WrLpcReply",
        "WrVirtualMemory", "WrPageOut", "WrRendezvous",
        "Spare2", "Spare3",  "Spare4", "Spare5", "Spare6", "WrKernel",
        "MaximumWaitReason"
    };
    if(waitRNum > 27){
        wprintf(L" \x1b[35mWaitReason:\x1b[0m Unknown\n");
    }else{
        wprintf(L" \x1b[35mWaitReason:\x1b[0m %s\n", waitReason[waitRNum]);
    }
}

/* void analyzeWaitTime(ULONG waitTime){ */
/*     if(waitTime > 0){ */
/*         DWORD hours = waitTime / 3600000; */
/*         DWORD minutes = (waitTime % 3600000) / 60000; */
/*         DWORD seconds = (waitTime % 60000) / 1000; */
/*         DWORD ms = waitTime % 1000; */

/*         printf("\x1b[34mWaitTime:\x1b[0m "); */
/*         if(hours > 0) printf("%luh:", hours); */
/*         if(minutes > 0) printf("%lum:", minutes); */
/*         if(seconds > 0) printf("%lus:", seconds); */
/*         printf("%lums:\n", ms); */
/*     } */
/* } */


void detailThreadsInformation(SYSTEM_THREAD_INFORMATION *sti, ULONG n_Threads){
    for(ULONG i = 0; i < n_Threads; i++){
        wprintf(L" \x1b[36mThreadID:\x1b[0m %-7lu ",
                (DWORD)(ULONG_PTR) sti[i].ClientId.UniqueThread);
        const wchar_t* stateString =
            (const wchar_t*)printThreadState(sti[i].ThreadState);
        wprintf(L" \x1b[32mState:\x1b[0m %hs ", stateString);
        if(sti[i].ThreadState == 5){
            printWaitReason(sti[i].WaitReason);
        }else{
            wprintf(L"\n");
        }
        /* analyzeWaitTime(sti[i].WaitTime); //WaitTime not a member Fk */
    }
}

int main(){

    NTSTATUS status;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    do{
        buffer = malloc(bufferSize);
        if(!buffer) return 1;
        status = NtQuerySystemInformation(
                                          SystemProcessInformation,
                                          buffer,
                                          bufferSize,
                                          &bufferSize
                                          );
        if(status == STATUS_INFO_LENGTH_MISMATCH){
            free(buffer);
            buffer = NULL;
        }
    }while(status == STATUS_INFO_LENGTH_MISMATCH);

    if(!NT_SUCCESS(status)){
        printf("NtQuerySystemInformation failed:0x%lx\n", status);
        return 1;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while(TRUE){
        puts("\n------------------------------------");
        DWORD pid = (DWORD)(ULONG_PTR)spi->UniqueProcessId;
        ULONG n_Threads = spi->NumberOfThreads;
        
        printf(" \x1b[32mPID:\x1b[0m %-6lu \x1b[36mThreads:\x1b[0m %-4lu \n", pid, n_Threads);

        PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)(spi + 1);
        detailThreadsInformation(sti, n_Threads);

        printf("\n");
        
        if(spi->ImageName.Buffer && spi->ImageName.Length > 0){
            wprintf(L" \x1b[34mImageName:\x1b[0m %.*ls \n",
                    spi->ImageName.Length / sizeof(WCHAR),
                    spi->ImageName.Buffer
                    );
        }else{
            wprintf(L" \x1b[34mImageName:\x1b[0m [System Idle Process]\n", pid);
        }

        HANDLE hProcess = NULL;
        OBJECT_ATTRIBUTES objAttri;
        InitializeObjectAttributes(&objAttri, NULL, 0, NULL, NULL);
            
        CLIENT_ID clientID = {0};
        clientID.UniqueProcess = (HANDLE)(ULONG_PTR)pid;//Don't forget to check this output
        clientID.UniqueThread = NULL;
        
        //OpenProcess [entry]
        NTSTATUS status = NtOpenProcess(&hProcess,
                                        PROCESS_QUERY_LIMITED_INFORMATION,
                                        &objAttri,
                                        &clientID);
        if(NT_SUCCESS(status)){
            callNtQueryInformationProcess(hProcess, ProcessBasicInformation);
            NtClose(hProcess);
        }else{
            printf(" \n\x1b[31mNtOpenProcess failed:\x1b[0m0x%lx\n ", status); 
        }
        puts("\n-----------------------------------");
        NtClose(hProcess);
        if(spi->NextEntryOffset == 0)
            break;

        spi = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)spi + spi->NextEntryOffset);
    }
    
    free(buffer);
    return 0;
}
