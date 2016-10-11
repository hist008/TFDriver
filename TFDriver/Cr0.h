
#include <ntddk.h>
//设置为不可写
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
		DbgPrint("DisableWrite执行失败！");
	}
}
// 设置为可写
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
		DbgPrint("EnableWrite执行失败！");
	}
}