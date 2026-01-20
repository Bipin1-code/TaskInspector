/*
  Date: 20-Jan-2026
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
        
        printf(" \x1b[32mPID:\x1b[0m %-6lu \x1b[36mThreads:\x1b[0m %-4lu ", pid, n_Threads);
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
