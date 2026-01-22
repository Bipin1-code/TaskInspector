/*
  Date: 20-Jan-2026 + 21-Jan-2026
  Task Manager recreation with NT APIs
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

static const char* states[] = {
    "Initialized", "Ready", "Running", "Standby",
    "Terminated", "Waiting", "Transition", "DeferredReady",
};

static const char* waitReason[] = {
    "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution",
    "Suspended", "UserRequest", "WrExecutive", "WrFreePage", "WrPageIn",
    "WrPoolAllocation", "WrDelayExecution", "WrSuspended", "WrUserRequest",
    "WrEventPair", "WrQueue", "WrLpcReceive","WrLpcReply",
    "WrVirtualMemory", "WrPageOut", "WrRendezvous",
    "Spare2", "Spare3",  "Spare4", "Spare5", "Spare6", "WrKernel",
    "MaximumWaitReason"
};

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

void printThreadState(ULONG state){

    if(state <= ARRAYSIZE(states)){
        wprintf(L" \x1b[32mState:\x1b[0m %hs ", states[state]);
    }else{
        wprintf(L" \x1b[32mState:\x1b[0m  Unknown "); 
    }
}

void printWaitReason(ULONG waitRNum){
   
    if(waitRNum >= ARRAYSIZE(waitReason)){
        wprintf(L" \x1b[35mWaitReason:\x1b[0m Unknown\n");
    }else{
        wprintf(L" \x1b[35mWaitReason:\x1b[0m %s\n", waitReason[waitRNum]);
    }
}

const char* getBasePriorityName(LONG basePriority){
    switch(basePriority){
        case 1: return "IDLE";
        case 4:  return "LOWEST";
        case 6:  return "BELOW_NORMAL";
        case 8:  return "NORMAL";
        case 10: return "ABOVE_NORMAL";
        case 15: return "HIGHEST";
        case 31: return "TIME_CRITICAL";
        default: return "UNKNOWN";   
    }
}

//Drop this idea now
//Wait Time idea:

//Thread Key (identity)
/* typedef struct{ */
/*     DWORD pid; //ProcessID */
/*     DWORD tid; //ThreadID */
/* } THREAD_KEY; */


/* //Per-thread state */
/* typedef struct{ */
/*     THREAD_KEY key; */
    
/*     ULONG lastThreadState; */
/*     ULONG lastWaitReason; */
    
/*     ULONGLONG lastTimestamp; */
/*     ULONGLONG totalWaitTime; */

/*     ULONGLONG lastKernelTIme; */
/*     ULONGLONG lastUserTime; */

/*     ULONG lastSeenEpoch;  */
    
/* } THREAD_RECORD; */

/* //Global tracker */
/* typedef struct{ */
/*     THREAD_RECORD *threads; */
/*     size_t count; */
/*     size_t capacity; */

/*     ULONG currentEpoch; */
/* } THREAD_TRACKER; */

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

/* void fillThreadRecord(THREAD_RECORD *trackerThreads, DWORD pid, DWORD tid, ULONG tState, ULONG wReason){ */
/*     trackerThreads->key.pid = pid; */
/*     trackerThreads->key.tid = tid; */
/*     //Don't have sufficient and stable infromation provided by NT      */
/* } */

void detailThreadsInformation(SYSTEM_THREAD_INFORMATION *sti, DWORD pid, ULONG n_Threads){

    /* THREAD_TRACKER tracker = {0}; */
    /* tracker.count = 0; */
    /* tracker.capacity = n_Threads; */
    (void)pid;
    
    for(ULONG i = 0; i < n_Threads; i++){

        DWORD tid = (DWORD)(ULONG_PTR) sti[i].ClientId.UniqueThread;
        wprintf(L" \x1b[36mThreadID:\x1b[0m %-7lu ", tid);

        ULONG threadState = sti[i].ThreadState;
        printThreadState(threadState);

        //Not meaningfull
        // printf(" \x1b[34mStartAddress:\x1b[0m %p  ", (void*)sti[i].StartAddress);
        

        LONG basePriority = sti[i].BasePriority;
        float dynamicPriority = (float)sti[i].Priority;
        float dynamicPriorityPercent = (dynamicPriority * 100.0f) / 32.0f;
        printf("\x1b[33mKPriority:\x1b[0m %.1f%%\x1b[33m BasePriority:\x1b[0m %s",
                dynamicPriorityPercent,
                getBasePriorityName(basePriority));

        ULONG waitReason = sti[i].WaitReason;
       
        //5 means waiting and 6 means Transition
        if(threadState == 5 || threadState == 6){
            if(threadState == 5){
                printWaitReason(waitReason);
            }
            /* fillThreadRecord(&tracker.threads[i], pid, tid, threadState, waitReason,); */
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

        //Threads Details Info
        PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)(spi + 1);
        detailThreadsInformation(sti, pid, n_Threads);
        printf("\n");
        
        //Name of the file the process belongs
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
        clientID.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
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
