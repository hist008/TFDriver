#pragma once
#ifdef __cplusplus
extern "C"
{
#endif
#include <ntifs.h>
#include <NTDDK.h> //这里包含需要用C方式编译的头文件
#ifdef __cplusplus
}
#endif 




#define PAGEDCODE code_seg("PAGE")
#define LOCKEDCODE code_seg()
#define INITCODE code_seg("INIT")

#define PAGEDDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

#define ALLOCTE_Page_TAG    (ULONG)'Hell'
#define ALLOCTE_NonPage_TAG (ULONG)0x44332211

#define DEVICE_NAME  L"\\Device\\Lyq"
#define SYMBOL_NAME  L"\\DosDevices\\LyqDevice"


#define USER_FUNC	0X800
#define USER_WRITE_FUNC	0X800+1 
#define USER_READ_FUNC	0X800+2	

#define IOCTL_USER_READ_FUNC \
	CTL_CODE(FILE_DEVICE_UNKNOWN,USER_READ_FUNC,METHOD_BUFFERED,FILE_ANY_ACCESS)


#define IOCTL_USER_WRITE_FUNC \
	CTL_CODE(FILE_DEVICE_UNKNOWN,USER_WRITE_FUNC,METHOD_BUFFERED,FILE_ANY_ACCESS)


// {2CF5D2D0-7C0E-4F03-8FFB-9FC6A8722BE5}
DEFINE_GUID(MY_WDM_DEVICE, 
			0x2cf5d2d0, 0x7c0e, 0x4f03, 0x8f, 0xfb, 0x9f, 0xc6, 0xa8, 0x72, 0x2b, 0xe5);

typedef struct _Irp_Pending_List
{
	PIRP PIRP;
	LIST_ENTRY ListEntry;
}Irp_Pending_List,*PIrp_Pending_List;

typedef struct _DEVICE_EXTENSION
{
	PDEVICE_OBJECT pDevice;				//本驱动的设备
	UNICODE_STRING strDeviceName;		//设备名称  
	UNICODE_STRING strSymLinkName;		//符号链接名  
	PDEVICE_OBJECT pDevFilterCom;		//过滤的设备
	PDEVICE_OBJECT  PhysicalDeviceObject;//真实的物理设备
	PLIST_ENTRY pIRPLinkListHead;
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;


PIRP g_PendindIrp = NULL;

NTSTATUS CreateDevice(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS status = 0 ;
	UNICODE_STRING strDeviceName;
 	PDEVICE_OBJECT pDeviceObject;
	PDEVICE_EXTENSION pDevExt ;
	RtlInitUnicodeString(&strDeviceName,DEVICE_NAME);
	status = IoCreateDevice(DriverObject,sizeof(DEVICE_EXTENSION),&strDeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&pDeviceObject);
 	if( NT_SUCCESS(status) ) 
	{
		DbgPrint("CreateDevice Ok\n");	
	}  

	pDeviceObject->Flags |= DO_BUFFERED_IO ;
 

	
 	UNICODE_STRING strDeviceSymbolName;
	RtlInitUnicodeString(&strDeviceSymbolName,SYMBOL_NAME);
	status = IoCreateSymbolicLink (&strDeviceSymbolName,&strDeviceName);
	if( NT_SUCCESS(status) ) 
	{
		DbgPrint("CreateSymbol Ok\n");		
	} 

	pDevExt = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
	pDevExt->pDevice = pDeviceObject;
	pDevExt->strDeviceName = strDeviceName;
	pDevExt->strSymLinkName = strDeviceSymbolName;
	//InitializeListHead(pDevExt->pIRPLinkListHead);


	//UNICODE_STRING strCom;
	//PFILE_OBJECT   pFileObj;
	//RtlInitUnicodeString(&strCom,L"\\Device\\Serial0");
	//status = IoGetDeviceObjectPointer(&strCom,FILE_ALL_ACCESS,&pFileObj,&pDevExt->pDevFilterCom);
	//if ( !NT_SUCCESS(status))
	//{
	//	DbgPrint("attach error\n");
	//}
	//ObDereferenceObject(pFileObj);

	//PDEVICE_OBJECT pAttDev = IoAttachDeviceToDeviceStack(pDeviceObject,pDevExt->pDevFilterCom);
	//if (pAttDev == NULL )
	//{
	//	DbgPrint("Attach Error\n");
	//}
	//else
	//{
	//	DbgPrint("Attach Driver Name is %wZ\n",pAttDev->DriverObject->DriverName);
	//}
	return status ;
}

void DestroyDevice(IN PDRIVER_OBJECT DriverObject)
{
	PDEVICE_OBJECT DeviceObject= DriverObject->DeviceObject;
	PDEVICE_EXTENSION pDevExt ;
	while( DeviceObject != NULL )
	{		
		pDevExt = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
		PDEVICE_OBJECT DeviceObjectNext=DeviceObject->NextDevice;
		//if ( pDevExt->PhysicalDeviceObject != NULL )
		//{
		//	IoDetachDevice(pDevExt->PhysicalDeviceObject);
		//}
		IoDeleteSymbolicLink(&pDevExt->strSymLinkName);
		IoDeleteDevice(pDevExt->pDevice);
		DeviceObject =  DeviceObjectNext ;
	}
}



NTSTATUS
DriverDispatch(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
	PDEVICE_EXTENSION pDev = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension ;
	PUCHAR pcAddr = NULL ;
	ULONG len = 0 ;
	PIO_STACK_LOCATION  irpStack  = IoGetCurrentIrpStackLocation(Irp);
	ULONG uFunc = irpStack->MajorFunction;//区分IRP
	LARGE_INTEGER Offset ;

	if ( uFunc == IRP_MJ_READ )
	{
		pcAddr = (PUCHAR) Irp->AssociatedIrp.SystemBuffer ;
		len = irpStack->Parameters.Read.Length ;
		Offset = irpStack->Parameters.Read.ByteOffset ;

		//PIrp_Pending_List pIrpPending = (PIrp_Pending_List)ExAllocatePoolWithTag(PagedPool,sizeof(Irp_Pending_List),ALLOCTE_Page_TAG);
		//pIrpPending->PIRP = Irp ;
		//InsertTailList(pDev->pIRPLinkListHead,&pIrpPending->ListEntry);
		g_PendindIrp = Irp ;
		IoMarkIrpPending(Irp);
		return STATUS_PENDING;
	}
	else if ( uFunc == IRP_MJ_WRITE )
	{
		pcAddr = (PUCHAR) Irp->AssociatedIrp.SystemBuffer ;
		len = irpStack->Parameters.Write.Length ;
		Offset = irpStack->Parameters.Write.ByteOffset ;
		Irp->IoStatus.Information = len ;
	}
	else if ( uFunc == IRP_MJ_CLEANUP )
	{
		IoCompleteRequest(g_PendindIrp,IO_NO_INCREMENT);
		g_PendindIrp->IoStatus.Information = 0 ;
		g_PendindIrp->IoStatus.Status = 0 ;
		return STATUS_SUCCESS ;
	}
	else if ( uFunc == IRP_MJ_DEVICE_CONTROL )
	{
		ULONG uFunCode = irpStack->Parameters.DeviceIoControl.IoControlCode ;
		ULONG uInLen = irpStack->Parameters.DeviceIoControl.InputBufferLength ;
		ULONG uOutLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength ;
		switch (uFunCode)
		{
		case IOCTL_USER_WRITE_FUNC:
			{

			}
			break;
		case IOCTL_USER_READ_FUNC:
			{
				pcAddr = (PUCHAR)Irp->AssociatedIrp.SystemBuffer ;
				for (int i=0;i<uInLen;i++)
				{
					DbgPrint("%02x ",pcAddr[i]);
				}
				RtlFillMemory(Irp->AssociatedIrp.SystemBuffer,uOutLen,0x32);
				Irp->IoStatus.Information = uOutLen ;
			}
			break;
		default:
			break;
		}
	}
	Irp->IoStatus.Status = STATUS_SUCCESS ;
	IoCompleteRequest(Irp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


VOID
	MyDpc(
	IN struct _KDPC  *Dpc,
	IN PVOID  DeferredContext,
	IN PVOID  SystemArgument1,
	IN PVOID  SystemArgument2
	)
{
	DbgPrint("HAHAH\n");
}

#pragma LOCKEDCODE
void TestDpc()
{
	KDPC dpc ;
	KTIMER timer;
	KeInitializeDpc(&dpc,MyDpc,NULL);

	LARGE_INTEGER due;
	due.QuadPart = -10000* 1;

	KeInitializeTimerEx(&timer,NotificationTimer);
	KeSetTimer(&timer,due,&dpc);
	
}




NTSTATUS
	PnpAddDevice(
	IN PDRIVER_OBJECT  DriverObject,
	IN PDEVICE_OBJECT  PhysicalDeviceObject 
	)
{
	NTSTATUS status = STATUS_SUCCESS ;

	UNICODE_STRING strDeviceName;
	PDEVICE_OBJECT pDeviceObject;
	PDEVICE_EXTENSION pDevExt ;
	RtlInitUnicodeString(&strDeviceName,DEVICE_NAME);
	status = IoCreateDevice(DriverObject,sizeof(DEVICE_EXTENSION),
		&strDeviceName,FILE_DEVICE_UNKNOWN,FILE_DEVICE_SECURE_OPEN,FALSE,&pDeviceObject);
	if( NT_SUCCESS(status) ) 
	{
		DbgPrint("CreateDevice Ok\n");	
	}  
	pDeviceObject->Flags |= DO_BUFFERED_IO ;
	pDeviceObject->Flags &= ~ DO_DEVICE_INITIALIZING ;


	pDevExt = (PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;
	pDevExt->pDevice = pDeviceObject;
	pDevExt->PhysicalDeviceObject = PhysicalDeviceObject ;
	pDevExt->strDeviceName = strDeviceName ;
	PDEVICE_OBJECT pAttDev = IoAttachDeviceToDeviceStack(pDeviceObject,PhysicalDeviceObject);
	if (pAttDev == NULL )
	{
		DbgPrint("Attach Error\n");
	}

	//IoRegisterDeviceInterface(PhysicalDeviceObject,&MY_WDM_DEVICE,NULL,&pDevExt->strDeviceName);
	//IoSetDeviceInterfaceState(&pDevExt->strDeviceName,TRUE);
	return status ;
}

VOID
	MyCreateProcessNotify (
	__in HANDLE ParentId,
	__in HANDLE ProcessId,
	__in BOOLEAN Create
	)
{
	PEPROCESS process; 
	PsLookupProcessByProcessId(ProcessId,&process);
	if ( Create )
	{
		DbgPrint("[Create]The Process is  %s------Pid is %d\n",(char*)process + 0x174,ProcessId);
	} 
	else
	{
		DbgPrint("[Destroy]The Processis %s-------Pid is %d\n",(char*)process + 0x174,ProcessId);
	}
	ObDereferenceObject(process);
}


void TestProcess()
{
	NTSTATUS status = STATUS_SUCCESS ;
	status = PsSetCreateProcessNotifyRoutine(MyCreateProcessNotify,FALSE);
}

VOID 
	MyThreadStart( 
	IN PVOID  StartContext 
	)
{
	LARGE_INTEGER DueTime ;
	DueTime.QuadPart = -10000*1000*2;
	NTSTATUS status = STATUS_SUCCESS ;
	INT32 x = 0;
	while (true)
	{
		DbgPrint("the thread \n");
		x++ ; 
		if ( x== 10 )
			break;
		KeDelayExecutionThread(KernelMode,FALSE,&DueTime);
	}

	PsTerminateSystemThread(0xdead);
}


#pragma PAGEDCODE 
VOID 
	MyThreadStart1( 
	IN PVOID  StartContext 
	)
{
	NTSTATUS status = STATUS_SUCCESS ;


	DbgPrint("the thread1 \n");


	//OBJECT_ATTRIBUTES ObjectAttributes;
	//InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	//HANDLE hThread[2]={0};
	//status = PsCreateSystemThread(&hThread[0],GENERIC_ALL,&ObjectAttributes
	//	,NULL,NULL,MyThreadStart2,&hThread[0]);

	//KIRQL irql = KeGetCurrentIrql();
	//DbgPrint("the irql is  %d\n",irql);
	//ASSERT(irql <= APC_LEVEL ) ;

	////status = KeWaitForMultipleObjects(1,hThread,WaitAll,Executive,KernelMode,FALSE,NULL,NULL);
	//status = KeWaitForSingleObject(&hThread[0],Executive,KernelMode,FALSE,NULL);

	//ZwClose(hThread[0]);
	PsTerminateSystemThread(0xdead);
}




void TestMultiThread()
{
	NTSTATUS status = STATUS_SUCCESS ;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	HANDLE hThread[2]={0};
	CLIENT_ID clientid[2]={0};
	status = PsCreateSystemThread(&hThread[0],GENERIC_ALL,&ObjectAttributes
		,NULL,&clientid[0],MyThreadStart1,NULL);

	status = PsCreateSystemThread(&hThread[1],GENERIC_ALL,&ObjectAttributes
		,NULL ,&clientid[1],MyThreadStart,NULL);

	PETHREAD  ethread[2]={0};

	status = PsLookupThreadByThreadId(clientid[0].UniqueThread,&ethread[0]);
	status = PsLookupThreadByThreadId(clientid[1].UniqueThread,&ethread[1]);
	
	PVOID pv[2]={ethread[0],ethread[1]};

	//LARGE_INTEGER timeout;;
	//timeout.QuadPart = -10000*1000*20 ;
	status = KeWaitForMultipleObjects(2,pv,WaitAll,Executive,KernelMode,FALSE,NULL,NULL);
	ObDereferenceObject(ethread[0]);
	ObDereferenceObject(ethread[1]);
	ZwClose(hThread[0]);
	ZwClose(hThread[1]);
	DbgPrint("test thread end\n");
}


VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) 
{
	//PsSetCreateProcessNotifyRoutine(MyCreateProcessNotify,TRUE);
	DbgPrint("DriverUnload Unload...\n");
	DestroyDevice(DriverObject);
	return;
}


#pragma LOCKEDCODE
VOID
	DriverStartIO(
	__inout struct _DEVICE_OBJECT *DeviceObject,
	__inout struct _IRP *Irp
	)
{

}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS ;
	_asm INT 3;
	int i=0 ;
	//DriverObject->DriverExtension->AddDevice = PnpAddDevice ;
	DriverObject->DriverStartIo = DriverStartIO ;
    DriverObject->DriverUnload = DriverUnload; 
	for ( i=0;i<=IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		DriverObject->MajorFunction[i] = DriverDispatch ;
	}
	DbgPrint("DriverEntry Load...\n");
	DbgPrint("The RegistryPath is %wZ\n",RegistryPath);
	CreateDevice(DriverObject);
	////ShowDriverInfo(DriverObject);
	return status;
}