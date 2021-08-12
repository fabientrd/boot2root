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

