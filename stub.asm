bits 64

pushfq
push rdi
push rsi
push rcx
push rdx
push rbp

;write description
mov rax, 0x3a
push rax
mov rax, 0x64726f7773736170
push rax
mov rax, 0x0a
push rax
mov rax, 0x3436786e69687073
push rax

mov rax, 1
mov rdi, 1
mov rsi, rsp
mov rdx, 32
syscall
add rsp, rdx

;mmap memory for password
mov rax, 9
xor rdi, rdi
mov rsi, 512
mov rdx, 3
mov r10, 34
mov r8, -1
xor r9, r9
syscall

;read password from stdin
mov rdi, 1
mov rsi, rax 
xor rax, rax
mov rdx, 512 ;one time pad available :D
syscall

;calculate its length
mov rcx, -1
mov rax, rsi
length_loop_start:
inc rcx
cmp byte[rax+rcx], 0x0a
jne length_loop_start

;run xor cipher
mov rdx, rsi		;key
mov rdi, 0x%x		;p_text_vaddr+s_text_off
mov rsi, 0x%x		;s_text_size
					;rcx contains key length

add rsi, rdi

xor r8, r8			;key_len counter
loop_start:			;loop text_memsz times
mov r9b, [rdx+r8]
xor r9b, [rdi]
mov [rdi], r9b
inc r8
inc rdi
cmp r8, rcx
jl less_than
xor r8, r8
less_than:
cmp rdi, rsi
jl loop_start

;[r8, r9, r10, r11] are volatile, no need to backup
pop rbp
pop rdx
pop rcx
pop rsi
pop rdi
popfq
mov rax, 0x%x
jmp rax
