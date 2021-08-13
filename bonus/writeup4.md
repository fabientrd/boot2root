## BONUS 2

Cette fois comme pour le bonus 1 nous allons devoir etre deja log en tant que root pour pouvoir utiliser cet exploit, mais ce n'est pas un probleme pour nous désormais !

Cette fois c'est le fichier /etc/sudoers que nous allons modifier et nous allons donner a laurie les meme droits que root :

```
#
# This file MUST be edited with the 'visudo' command as root.
#
# Please consider adding local content in /etc/sudoers.d/ instead of
# directly modifying this file.
#
# See the man page for details on how to write a sudoers file.
#
Defaults	env_reset
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Host alias specification

# User alias specification

# Cmnd alias specification

# User privilege specification
root	ALL=(ALL:ALL) ALL
laurie  ALL=(ALL:ALL) ALL
# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# See sudoers(5) for more information on "#include" directives:

#includedir /etc/sudoers.d
root@BornToSecHackMe:/home/laurie# exit
exit
laurie@BornToSecHackMe:~$ sudo su root
[sudo] password for laurie:
root@BornToSecHackMe:/home/laurie#
```

Ici nous avons donné les memes droits a laurie que pour root nous avons donc juste a faire sudo su root et de mettre en password celui de laurie pour etre de nouveau log en tant que root.

