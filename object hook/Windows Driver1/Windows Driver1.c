#include <ntddk.h>



/*这两个结构是根据windbg从win7-32-bits里面荡出来的*/
typedef struct _OBJECT_TYPE_INITIALIZER
{
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN CaseInsensitive;
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG RetainAccess;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	ULONG DumpProcedure;
	ULONG OpenProcedure;
	ULONG CloseProcedure;
	ULONG DeleteProcedure;
	ULONG ParseProcedure;
	ULONG SecurityProcedure;
	ULONG QueryNameProcedure;
	ULONG OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	UCHAR Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	ULONG TypeLock;
	ULONG Key;
	LIST_ENTRY CallBackList;
}OBJECT_TYPE, *POBJECT_TYPE;

typedef enum _OB_OPEN_REASON   
{                               
	ObCreateHandle,             
	ObOpenHandle,
	ObDuplicateHandle,
	ObInheritHandle,
	ObMaxOpenReason
} OB_OPEN_REASON;

typedef NTSTATUS (*OB_OPEN_METHOD)(        
	ULONG Unknow,								//win2k里面只有五个参数，win7下有六个，第一个不知道干什么用的
	OB_OPEN_REASON Reason,		 
	PEPROCESS Process,
	PVOID Object,
	ACCESS_MASK GrantedAccess,
	ULONG HandleCount);

//未导出函数，声明下就可以使用
extern POBJECT_TYPE ObGetObjectType(PVOID Object);

extern UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);;

ULONG old_OpenProcedure;

void PageProtectOff()
{
	_asm
	{
		cli;
		mov eax, cr0;
		and eax, not 10000h;
		mov cr0, eax;
	}
}

void PageProtectOn()
{
	_asm
	{
		mov eax, cr0;
		or eax, 10000h;
		mov cr0, eax;
		sti;
	}
}

NTSTATUS MyOenProcedure(
	ULONG Unknow,		
	OB_OPEN_REASON Reason,
	PEPROCESS Process,
	PEPROCESS TagProcess,
	ACCESS_MASK GrantedAccess,
	ULONG HandleCount)
{
	if (strstr(PsGetProcessImageFileName(TagProcess), "calc"))
	{
		KdPrint(("禁止打开计算器！\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return ((OB_OPEN_METHOD)old_OpenProcedure)(Unknow, Reason, Process, TagProcess, GrantedAccess, HandleCount);
}

//Flag为1代表开启HOOK，Flag为0代表关闭HOOK
VOID ObjectHook(ULONG Flag)
{
	PEPROCESS CurrentProcess;
	POBJECT_TYPE ObjectType;

	//获取当前的进程对象
	CurrentProcess = PsGetCurrentProcess();
	//获取进程对象对应的ObjectType
	ObjectType = ObGetObjectType(CurrentProcess);

	if (Flag)
	{
		//获取旧的OpenProcedure
		old_OpenProcedure = ObjectType->TypeInfo.OpenProcedure;
		//赋值新的OpenProcedure替代
		ObjectType->TypeInfo.OpenProcedure = (ULONG)MyOenProcedure;
	}
	else
		ObjectType->TypeInfo.OpenProcedure = old_OpenProcedure;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	ObjectHook(0);
	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	ObjectHook(1);
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}