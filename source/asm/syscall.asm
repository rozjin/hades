[bits 64]
[extern syscall_handler]

section .note.GNU-stack noalloc noexec nowrite progbits
section .text	
    %macro pushaq 0
        push rax
        push rbx
        push rcx
        push rdx
        push rbp
        push rdi
        push rsi
        push r8
        push r9
        push r10
        push r11
        push r12
        push r13
        push r14
        push r15
    %endmacro

    %macro popaq 0
        pop r15
        pop r14
        pop r13
        pop r12
        pop r11
        pop r10
        pop r9
        pop r8
        pop rsi
        pop rdi
        pop rbp
        pop rdx
        pop rcx
        pop rbx
        pop rax
    %endmacro

    [global syscall_enter]
	syscall_enter:
        swapgs

        mov qword [gs:8], rsp
        mov rsp, qword [gs:0]

        push 0x23
        push qword [gs:8]
        push r11
        push 0x1B
        push rcx

        push 0
        push 0

        pushaq
        cld

        mov rdi, rsp
        call syscall_handler

        popaq
        add rsp, 16
        
        swapgs

        iretq

    [global x86_sigreturn_exit]
    x86_sigreturn_exit:
        mov rsp, rdi

        popaq

        add rsp, 16

        iretq