#pragma once
#include <ntddk.h>
// KSYSTEM_SERVICE_TABLE �� KSERVICE_TABLE_DESCRIPTOR
// �������� SSDT �ṹ
typedef struct _KSYSTEM_SERVICE_TABLE
{
	PULONG  ServiceTableBase;                               // SSDT (System Service Dispatch Table)�Ļ���ַ
	PULONG  ServiceCounterTableBase;                        // ���� checked builds, ���� SSDT ��ÿ�����񱻵��õĴ���
	ULONG   NumberOfService;                                // �������ĸ���, NumberOfService * 4 ����������ַ��Ĵ�С
	ULONG   ParamTableBase;                                 // SSPT(System Service Parameter Table)�Ļ���ַ
} KSYSTEM_SERVICE_TABLE, *PKSYSTEM_SERVICE_TABLE;

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	KSYSTEM_SERVICE_TABLE   ntoskrnl;                       // ntoskrnl.exe �ķ�����
	KSYSTEM_SERVICE_TABLE   win32k;                         // win32k.sys �ķ�����(GDI32.dll/User32.dll ���ں�֧��)
	KSYSTEM_SERVICE_TABLE   notUsed1;
	KSYSTEM_SERVICE_TABLE   notUsed2;
}KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

//����Ϊ����д
void DisableWrite();
// ����Ϊ��д
void EnableWrite();