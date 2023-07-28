
# Générateur de shellcode polymorphique



```                                                     
 _____     _     _____ _       _ _ _____       _     
|  _  |___| |_ _|   __| |_ ___| | |     |___ _| |___ 
|   __| . | | | |__   |   | -_| | |   --| . | . | -_|
|__|  |___|_|_  |_____|_|_|___|_|_|_____|___|___|___|
            |___|                                    

```

Ce programme Python a été créé dans un but éducatif afin de générer des shellcodes de reverse shell uniques à chaque exécution. Son objectif est de fournir des exemples variés de shellcodes de reverse shell à chaque fois que le programme est appelé.

## Installation et utilisation

```bash
git clone https://github.com/OxyDeV2/Shellcode-generator-metamorphism
cd Shellcode-generator-metamorphism
```

```bash
python generateur.py [IP] [PORT]
```


```bash

```

Le fichier "loader.c" est conçu pour tester votre shellcode. Il est crucial de désactiver les protections d'exécution de la pile (Stack Execution Protection) et l'adressage aléatoire (Address Space Layout Randomization - ASLR).

L'objectif de "loader.c" est de créer un environnement propice à l'exécution de votre shellcode sans rencontrer de problèmes liés à ces protections. En désactivant ces mécanismes de sécurité, le shellcode peut s'exécuter correctement et démontrer son fonctionnement sans être entravé par des restrictions de sécurité supplémentaires.

```c
gcc loader.c -w -fno-stack-protector -z execstack -no-pie -o shellcodeloader.bin
```

Après avoir généré votre shellcode, remplacez-le dans le fichier "loader.c" et exécutez votre binaire.

```bash
./shellcode.bin
```
## Contributeurs
- [OxyDeV2](https://github.com/OxyDeV2) #Github
- [Skriix](https://github.com/Skriix) #Github
