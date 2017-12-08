# Signature-Electronique
Le projet traite une applet JavaCard permettant la signature tout type de documents:

L’applet doit être sécurisé avec un code PIN et code PUK.
Le PUK débloque le PIN en cas de soumission d’un PIN erroné trois fois de suite.

L’applet doit générer dans sa phase d’installation une paire de clé RSA 512 bits  . 

Dans sa phase de personnalisation, l’applet doit : 
1- Mettre à jour le code PIN et code PUK ;
2- Permettre la lecture de la clé publique de la carte ; 
L’applet ne valide cette phase que si les trois opérations ont été réalisées;

L’applet va ensuite entrer dans la phase utilisation qui permet de réaliser les instructions:
1- Mettre à jour du code PIN en vérifiant l’ancien code PIN ; 
2- Permettre de recevoir un fichier de taille 128 bytes ; 
3- Signer le fichier à l’aide de clé privée ; 
4- Récupérer la signature du fichier.  


