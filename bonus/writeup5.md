## BONUS 3

Pour ce bonus tout va se passer directement depuis l'écran de la VM.

Au démarrage d'un VM, le fait d'appuyer sur la touche `shift` va nous ouvrir Grub boot manager. Nous nous retrouvons donc avec un écran noir avec une ligne de commande commencant par boot.

Lorsque l'on essaye de rentrer root, la machine nous dit :

```
boot : root
Could not find kernel image : root
```

Essayons de trouver les images disponibles grace a la touche `tab`

```
boot:
  live
```

Nous avons donc plus qu'à rentrer la commande suivante pour etre boot en tant que root :

```
boot: live init=/bin/bash
```

[Grub](../photos/b2r_3.png)

Et voila nous sommes root !

Alors pourquoi Linux autorise t-il init=/bin/bash ??

Il s'agit d'une fonctionnalité utilisée pour la maintenance du système: elle permet à un administrateur système de récupérer un système à partir de fichiers d'initialisation corrompus ou de modifier un mot de passe oublié. Dans les systèmes de type Unix, init est le premier processus à être exécuté et l'ancêtre ultime de tous les processus jamais exécutés. Il est responsable de l'exécution de tous les scripts d'initialisation. Ici nous disons donc au noyau Linux d'executer /bin/bash en tant que init plutot que de lancer une vraie initialisation.

Si on veut  "réparer" ceci, il faut verrouiller GRUB et notre BIOS avec un mot de passe et mettre le disque dur en premier dans l'ordre de démarrage.
