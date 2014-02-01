
#include <windows.h>


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_(MaximumLength, Length) PWCH   Buffer;
} UNICODE_STRING;

struct ProcInfo
{
    LPVOID LdrLoadDllRoutine;
    HANDLE dllHandle;
    UNICODE_STRING dllName;
    WCHAR nameString[20];
};

void memset1(void* dest,int val,int size)
{
    for(int i=0;i<size;i++)
        ((BYTE*)dest)[i]=val;
}

__declspec(naked) int LoadLib()
{
    __asm{
        call lbl
lbl:
        pop ecx
        mov ebx,eax
        lea eax,[ecx-0x55+4]
        push eax
        lea eax,[ecx-0x55+8]
        push eax
        xor eax,eax
        push eax
        push eax
        call [ecx-0x55]
        jmp ebx
    }
}

BOOL CreateAndInject(TCHAR* appName, TCHAR* dllName)
{
    PROCESS_INFORMATION pi;
    STARTUPINFO si;

    if(lstrlen(dllName)>=20)
        return FALSE;

    memset1(&si,0,sizeof(si));
    si.cb=sizeof(si);

    if(GetFileAttributes(appName)==-1)
        return FALSE;

    if(!CreateProcess(0,appName,0,0,FALSE,CREATE_SUSPENDED,0,0,&si,&pi))
        return FALSE;

    BYTE* newMem=(BYTE*)VirtualAllocEx(pi.hProcess,0,0x100,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    if(!newMem)
    {
        TerminateProcess(pi.hProcess,0);
        return FALSE;
    }

    ProcInfo procInfo;
    procInfo.LdrLoadDllRoutine=GetProcAddress(GetModuleHandle(L"ntdll.dll"),"LdrLoadDll");
    lstrcpy(procInfo.nameString,dllName);
    procInfo.dllName.Buffer=((ProcInfo *)newMem)->nameString;
    procInfo.dllName.Length=lstrlen(dllName)*2;
    procInfo.dllName.MaximumLength=sizeof(procInfo.nameString)*2;

    DWORD bytesWrote=0;
    BOOL wroteSuccess=TRUE;
    wroteSuccess =wroteSuccess && WriteProcessMemory(pi.hProcess,newMem,&procInfo,sizeof(procInfo),&bytesWrote);

    wroteSuccess =wroteSuccess && WriteProcessMemory(pi.hProcess,newMem+0x50,LoadLib,0x50,&bytesWrote);

    if(!wroteSuccess)
    {
        TerminateProcess(pi.hProcess,0);
        return FALSE;
    }

    ResumeThread(pi.hThread);

    return TRUE;
}