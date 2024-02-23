.data
	SSN DWORD 0h
	JumpAddress QWORD 0h

.code


public SetSyscallValues
SetSyscallValues proc
	
	mov SSN, ecx
	mov JumpAddress, rdx
	ret

SetSyscallValues endp



public SyscallGeneric
SyscallGeneric proc
	
	mov r10, rcx
	mov eax, SSN
	jmp qword ptr [JumpAddress]
	ret
	
SyscallGeneric endp


end