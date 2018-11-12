#pragma once

#include <ntddk.h>
#include <windef.h>
#include <ntstatus.h>

__int64 __readmsr(int register);
unsigned __int64 __readcr0(void);
void __writecr0(
	unsigned __int64 Data
);
void _disable(void);
void _enable(void);

KIRQL WPOFFx64();
void WPONx64(KIRQL irql);
ULONGLONG GetKeServiceDescriptorTable64();
PULONG GetSSDTBaseAddress();
ULONG GetOffsetAddress(ULONGLONG FuncAddr, CHAR paramCount);
VOID HookSSDT();
VOID UnhookSSDT();
void DriverUnload(PDRIVER_OBJECT pDriver);
ULONGLONG GetFuncAddr(ULONG id);

//_SYSTEM_SERVICE_TABLE结构声明
typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
	SYSTEM_SERVICE_TABLE ntoskrnl;  // ntoskrnl.exe (native api)
	SYSTEM_SERVICE_TABLE win32k;    // win32k.sys   (gdi/user)
	SYSTEM_SERVICE_TABLE Table3;    // not used
	SYSTEM_SERVICE_TABLE Table4;    // not used
}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

NTKERNELAPI UCHAR * PsGetProcessImageFileName(PEPROCESS Process);

//定义NTOPENPROCESS
typedef NTSTATUS(__stdcall *NTOPENPROCESS)(OUT PHANDLE  ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes,
	IN OPTIONAL PCLIENT_ID  ClientId);

NTOPENPROCESS OldOpenProcess = NULL;
ULONG OldTpVal;
