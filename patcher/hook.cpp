#include <windows.h>
#include "ilhook.h"

#pragma comment(linker,"/entry:DllMain")

typedef struct _FILE_BOTH_DIR_INFORMATION {

    ULONG                   NextEntryOffset;
    ULONG                   FileIndex;
    LARGE_INTEGER           CreationTime;
    LARGE_INTEGER           LastAccessTime;
    LARGE_INTEGER           LastWriteTime;
    LARGE_INTEGER           ChangeTime;
    LARGE_INTEGER           EndOfFile;
    LARGE_INTEGER           AllocationSize;
    ULONG                   FileAttributes;
    ULONG                   FileNameLength;
    ULONG                   EaSize;
    BYTE                    ShortNameLength;
    WCHAR                   ShortName[12];
    WCHAR                   FileName[1];


} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;
typedef struct _FILE_BASIC_INFORMATION {

    LARGE_INTEGER           CreationTime;
    LARGE_INTEGER           LastAccessTime;
    LARGE_INTEGER           LastWriteTime;
    LARGE_INTEGER           ChangeTime;
    ULONG                   FileAttributes;


} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;
typedef struct _FILE_NETWORK_OPEN_INFORMATION {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef int (WINAPI *NtQueryAttributesFileRoutine)(
    IN PVOID   ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileAttributes 
    );

typedef int (WINAPI *NtQueryDirectoryFileRoutine)(
    _In_      HANDLE FileHandle,
    _In_opt_  HANDLE Event,
    _In_opt_  PVOID ApcRoutine,
    _In_opt_  PVOID ApcContext,
    _Out_     PVOID IoStatusBlock,
    _Out_     PVOID FileInformation,
    _In_      ULONG Length,
    _In_      DWORD FileInformationClass,
    _In_      BOOLEAN ReturnSingleEntry,
    _In_opt_  PVOID FileName,
    _In_      BOOLEAN RestartScan
    );

typedef int (WINAPI *NtQueryFullAttributesFileRoutine)(
    _In_   PVOID ObjectAttributes,
    _Out_  PFILE_NETWORK_OPEN_INFORMATION FileInformation
    );

int WINAPI MyNtQueryDirectoryFile(
    NtQueryDirectoryFileRoutine func,
    _In_      HANDLE FileHandle,
    _In_opt_  HANDLE Event,
    _In_opt_  PVOID ApcRoutine,
    _In_opt_  PVOID ApcContext,
    _Out_     PVOID IoStatusBlock,
    _Out_     PVOID FileInformation,
    _In_      ULONG Length,
    _In_      DWORD FileInformationClass,
    _In_      BOOLEAN ReturnSingleEntry,
    _In_opt_  PVOID FileName,
    _In_      BOOLEAN RestartScan
    )
{
    int status=func(FileHandle,Event,ApcRoutine,ApcContext,IoStatusBlock,FileInformation,Length,FileInformationClass,
        ReturnSingleEntry,FileName,RestartScan);
    if(status>=0)
    {
        if(FileInformationClass==3)
        {
            PFILE_BOTH_DIR_INFORMATION fi=(PFILE_BOTH_DIR_INFORMATION)FileInformation;
            fi->FileAttributes &= (~FILE_ATTRIBUTE_REPARSE_POINT);
        }
    }
    return status;
}

int WINAPI MyNtQueryAttributesFile(NtQueryAttributesFileRoutine func,PVOID oa,PFILE_BASIC_INFORMATION fi)
{
    int status=func(oa,fi);
    if(status>=0)
    {
        fi->FileAttributes &= (~FILE_ATTRIBUTE_REPARSE_POINT);
    }
    return status;
}

int WINAPI MyNtQueryFullAttributesFile(NtQueryFullAttributesFileRoutine func,PVOID oa,PFILE_NETWORK_OPEN_INFORMATION fi)
{
    int status=func(oa,fi);
    if(status>=0)
    {
        fi->FileAttributes &= (~FILE_ATTRIBUTE_REPARSE_POINT);
    }
    return status;
}

int WINAPI DllMain( HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved )
{
    if(dwReason==DLL_PROCESS_ATTACH)
    {
        HMODULE hm=GetModuleHandle(L"ntdll.dll");
        LPVOID func=GetProcAddress(hm,"ZwQueryDirectoryFile");

        BYTE* buff=(BYTE*)VirtualAlloc(0,1000,MEM_COMMIT,PAGE_EXECUTE_READWRITE);

        HookSrcObject src;
        HookStubObject stub;

        if(!InitializeHookSrcObject(&src,func) ||
            !InitializeStubObject(&stub,buff,1000,44,STUB_DIRECTLYRETURN|STUB_OVERRIDEEAX) ||
            !Hook32(&src,0,&stub,MyNtQueryDirectoryFile,"f123456789AB"))
        {
            MessageBox(0,L"无法hook函数1",0,0);
            return FALSE;
        }
        
        func=GetProcAddress(hm,"ZwQueryAttributesFile");
        if(!InitializeHookSrcObject(&src,func) ||
            !InitializeStubObject(&stub,buff+100,900,8,STUB_DIRECTLYRETURN|STUB_OVERRIDEEAX) ||
            !Hook32(&src,0,&stub,MyNtQueryAttributesFile,"f12"))
        {
            MessageBox(0,L"无法hook函数2",0,0);
            return FALSE;
        }

        func=GetProcAddress(hm,"ZwQueryFullAttributesFile");
        if(!InitializeHookSrcObject(&src,func) ||
            !InitializeStubObject(&stub,buff+200,800,8,STUB_DIRECTLYRETURN|STUB_OVERRIDEEAX) ||
            !Hook32(&src,0,&stub,MyNtQueryAttributesFile,"f12"))
        {
            MessageBox(0,L"无法hook函数3",0,0);
            return FALSE;
        }
   }
    return TRUE;
}