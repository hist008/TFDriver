
#include <ntddk.h>
//����Ϊ����д
void DisableWrite()
{
	__try
	{
		_asm
		{
			mov eax, cr0 
				or  eax, 10000h 
				mov cr0, eax 
				sti 
		}
	}
	__except(1)
	{
		DbgPrint("DisableWriteִ��ʧ�ܣ�");
	}
}
// ����Ϊ��д
void EnableWrite()
{
	__try
	{
		_asm
		{
			cli
				mov eax,cr0
				and eax,not 10000h //and eax,0FFFEFFFFh
				mov cr0,eax
		}
	}
	__except(1)
	{
		DbgPrint("EnableWriteִ��ʧ�ܣ�");
	}
}