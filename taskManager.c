/*
  Date: 19-Jan-26
  Projects: Minimalistic Task Manager with the help of Win32
  APIs
*/

#define _WIN32_WINNT 0x0602 //annoying define even though I have newest version of windows
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h> //toolhelp api for snapshot apis
#include <processthreadsapi.h> //for getProcessInformation api

#define PROTECTION_TYPE_MASK    0x0F
#define PROTECTION_SIGNER_MASK  0xF0

#define PROTECTION_TYPE_NONE              0x0
#define PROTECTION_TYPE_PROTECTED_LIGHT   0x1
#define PROTECTION_TYPE_PROTECTED         0x2

#define PROTECTION_SIGNER_NONE         0x00
#define PROTECTION_SIGNER_WINDOWS     0x10
#define PROTECTION_SIGNER_WIN_TCB     0x20
#define PROTECTION_SIGNER_LSA         0x30
#define PROTECTION_SIGNER_ANTIMALWARE 0x40


void ProcessMemoryPriorityInfo(ULONG memoryPriority){
    switch(memoryPriority){
        case MEMORY_PRIORITY_VERY_LOW:
            puts(" Memory priority: Very Low ");
            break;
        case MEMORY_PRIORITY_LOW:
            puts(" Memory priority: Low ");
            break;
        case MEMORY_PRIORITY_MEDIUM:
            puts(" Memory priority: Medium ");
            break;
        case MEMORY_PRIORITY_BELOW_NORMAL:
            puts(" Memory priority: Below Normal ");
            break;
        case MEMORY_PRIORITY_NORMAL:
            puts(" Memory priority: Normal ");
            break;
    }
}

void ProcessPriorityClass(HANDLE hProcess){
    DWORD priority = GetPriorityClass(hProcess);
    switch(priority){
        case IDLE_PRIORITY_CLASS:
            printf(" Prority: Idle  ");
            break;

        case BELOW_NORMAL_PRIORITY_CLASS:
            printf(" Prority: Below Normal ");
            break;
        case NORMAL_PRIORITY_CLASS:
            printf("  Prority: Normal ");
            break;
        case ABOVE_NORMAL_PRIORITY_CLASS:
            printf("  Prority: Above Normal ");
            break;
        case HIGH_PRIORITY_CLASS:
            printf("  Prority: High priority  ");
            break;
        case REALTIME_PRIORITY_CLASS:
            printf("   Prority: Real Time  ");
            break;
   
        default:
            printf("  Prority: Unknown  ");
            break;
    }
}

void PrintProcessProtectionLevel(ULONG level){
    ULONG type   = level & PROTECTION_TYPE_MASK;
    ULONG signer = level & PROTECTION_SIGNER_MASK;

    printf("\x1b[32mProtection:\x1b[0m ");

    switch(type){
        case PROTECTION_TYPE_NONE:
            printf("None");
            break;
        case PROTECTION_TYPE_PROTECTED_LIGHT:
            printf("PPL");
            break;
        case PROTECTION_TYPE_PROTECTED:
            printf("Protected");
            break;
        default:
            printf("UnknownType");
    }

    printf(" \x1b[32m| Signer:\x1b[0m ");

    switch(signer){
        case PROTECTION_SIGNER_WINDOWS:
            printf("Windows");
            break;
        case PROTECTION_SIGNER_WIN_TCB:
            printf("WinTcb");
            break;
        case PROTECTION_SIGNER_LSA:
            printf("LSA");
            break;
        case PROTECTION_SIGNER_ANTIMALWARE:
            printf("Antimalware");
            break;
        default:
            printf("None/Unknown");
    }

    printf("\n");
}

int main(){
    HANDLE hSnap = CreateToolhelp32Snapshot(
                                            TH32CS_SNAPPROCESS,
                                            0
                                            );
    if(hSnap == INVALID_HANDLE_VALUE){
        printf("CreateToolhelp32Snapshot failed\n");
        return 1;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if(!Process32FirstW(hSnap, &pe)){
        CloseHandle(hSnap);
        return 1;
    }
    do{
        //I change this only on share output line
        printf("\n-----------------------------------------\n");
        
        HANDLE hEntryProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                           FALSE,
                                           pe.th32ProcessID);
        if(hEntryProcess == INVALID_HANDLE_VALUE){
            printf("[Error PID: %lu]", pe.th32ProcessID);
        }

          
        WCHAR processName[MAX_PATH];
        DWORD size = MAX_PATH;
        
        if(QueryFullProcessImageNameW(hEntryProcess, 0, processName, &size)){
            
            /* const wchar_t *sourceName = wcsrchr((wchar_t *)processName, L'\\'); */
            /* sourceName = sourceName ? sourceName + 1 : processName; */

            wchar_t fullName[MAX_PATH];
            wcsncpy(fullName, processName, MAX_PATH - 1);
            fullName[MAX_PATH - 1] = L'\0';

            wprintf(L" \x1b[32mName:\x1b[0m  %ls  \x1b[32mFullName:\x1b[0m %ls \n",
                    pe.szExeFile, fullName);
        }else{
            wprintf(L"  \x1b[32mName:\x1b[0m %ls  \x1b[32mFullName:\x1b[0m --- \n",
                    pe.szExeFile); 
        }

        wprintf(L" \x1b[32mPID:\x1b[0m %-6lu  \x1b[32mPPID:\x1b[0m %-6lu \x1b[32mThreads:\x1b[0m %-3u \n",
                pe.th32ProcessID,
                pe.th32ParentProcessID,
                pe.cntThreads);
        
        ProcessPriorityClass(hEntryProcess);

        MEMORY_PRIORITY_INFORMATION mpi;
        if(GetProcessInformation(hEntryProcess,
                                 ProcessMemoryPriority,
                                 &mpi,
                                 sizeof(mpi))){
            ProcessMemoryPriorityInfo(mpi.MemoryPriority);
        }
        printf("\n");
        PROCESS_POWER_THROTTLING_STATE pts = {0};
        pts.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION;

        if(GetProcessInformation(
                                 hEntryProcess,
                                 ProcessPowerThrottling,
                                 &pts,
                                 sizeof(pts))){
            if(pts.ControlMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED){
                printf(" \x1b[32mThrottle:\x1b[0m Enable/disable ");
            }
            if(pts.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED){
                printf(" \x1b[32mThrottled:\x1b[0m EFFICIENCY mode ");
            }else{
                printf(" \x1b[32mThrottled:\x1b[0m Running Normal ");
            }
        }

        PROCESS_PROTECTION_LEVEL_INFORMATION ppli;
        
        if(GetProcessInformation(
                                 hEntryProcess,
                                 ProcessProtectionLevelInfo,
                                 &ppli,
                                 sizeof(ppli))){
            PrintProcessProtectionLevel(ppli.ProtectionLevel);
        }
        

        
        DWORD exitCode;
        if(GetExitCodeProcess(hEntryProcess, &exitCode)){
            if(exitCode == STILL_ACTIVE)
                printf("  \x1b[32mSTATUS:\x1b[0m Running...  \n");
            else
                printf("  \x1b[32mSTATUS:\x1b[0m  Exited  \n");
        }

        APP_MEMORY_INFORMATION ami;

        if (GetProcessInformation(
                                  hEntryProcess,
                                  ProcessAppMemoryInfo,
                                  &ami,
                                  sizeof(ami)))
            {
                printf("\x1b[32mPrivate Commit:\x1b[0m %llu KB ",
                       ami.PrivateCommitUsage / 1024);
                printf(" \x1b[32m | Peak Commit:\x1b[0m %llu KB\n",
                       ami.PeakPrivateCommitUsage / 1024);
            }
      
        printf("-----------------------------------------\n");

        CloseHandle(hEntryProcess);
        
    }while(Process32NextW(hSnap, &pe));

    CloseHandle(hSnap);
    return 0;
}
