#include <ntddk.h>



/*�������ṹ�Ǹ���windbg��win7-32-bits���浴������*/
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
	ULONG Unknow,								//win2k����ֻ�����������win7������������һ����֪����ʲô�õ�
	OB_OPEN_REASON Reason,		 
	PEPROCESS Process,
	PVOID Object,
	ACCESS_MASK GrantedAccess,
	ULONG HandleCount);

//δ���������������¾Ϳ���ʹ��
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
		KdPrint(("��ֹ�򿪼�������\n"));
		return STATUS_UNSUCCESSFUL;
	}

	return ((OB_OPEN_METHOD)old_OpenProcedure)(Unknow, Reason, Process, TagProcess, GrantedAccess, HandleCount);
}

//FlagΪ1������HOOK��FlagΪ0����ر�HOOK
VOID ObjectHook(ULONG Flag)
{
	PEPROCESS CurrentProcess;
	POBJECT_TYPE ObjectType;

	//��ȡ��ǰ�Ľ��̶���
	CurrentProcess = PsGetCurrentProcess();
	//��ȡ���̶����Ӧ��ObjectType
	ObjectType = ObGetObjectType(CurrentProcess);

	if (Flag)
	{
		//��ȡ�ɵ�OpenProcedure
		old_OpenProcedure = ObjectType->TypeInfo.OpenProcedure;
		//��ֵ�µ�OpenProcedure���
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