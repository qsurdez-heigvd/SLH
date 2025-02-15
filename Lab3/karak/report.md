# Rapport
Author : Quentin Surdez


1. Voyez-vous des problèmes avec la politique spécifiée dans l’énoncé ?
> À mon échelle, j'observe qu'il n'y a pas de contraintes temporelles sur les différentes règles. Un 
> médecin-traitant ne devrait pas avoir, ad aeternam, l'accès au dossier d'un patient. Ensuite, on observe que le 
> patient ne peut pas choisir de cacher certains documents à son médecin-traitant. Ceci peut être important si le 
> patient va demander un second avis médical et ne souhaite pas en discuter avec son médecin. Le patient doit 
> pouvoir garder plein pouvoir sur ses données qu'importe l'autorité avec laquelle il dialogue.

2. Parmi les politiques définies ci-dessus, la ou lesquelles serai(en)t pénibles à implémenter s’il
fallait utiliser à la place d’ABAC un modèle RBAC traditionnel ?
> La politique qui permet aux médecins de voir les rapports de leurs patients serait particulièrement complexe a 
> implémenter comme elle repose sur une relation dynamique (à savoir la liste de médecins dans le dossier médical du 
> patient) plutôt que sur des rôles statiques. La solution à chaud serait de créer un rôle par relation 
> médecin-patient ce qui amènerait à une explosion de rôle. Ensuite, la relation de propriété me semble passablement 
> compliqué à adapter en RBAC. Le fait que l'utilisateur puisse voir son propre dossier ne me paraît pas trivial.

3. Que pensez-vous de l’utilisation d’un Option<UserID> mutable dans la structure Service pour
   garder trace de l’utilisateur loggué ? Comment pourrait-on changer le design pour savoir à la
   compilation si un utilisateur est censé être connecté ou pas ? Est-ce que cela premet d’éliminer
   une partie du traitement d’erreurs ?
> Comme l'application est en Rust et que ce langage est fortement typé, il serait intéressant d'avoir un autre objet 
> pour une session non authentifié, par exemple, cela nous permettrait de bien définir les contextes dans lesquels 
> l'utilisateur doit être connecté ou non.

4. Que pensez-vous de l’utilisation de la macro de dérivation automatique pour Deserialize pour
   les types de model ? Et pour les types de input_validation ?
> Il y a à la fois des avantages et des inconvénients. Pour les types de model, la dérivation automatique est bonne 
> et simple à mettre en place et ne pose que peu de problèmes de sécurité. Cependant, nous devons être prudents sur 
> la désérialisation automatique de tous les champs, en effet, pour certains types, ce comportement n'est pas 
> forcément celui souhaité. Ensuite, pour les types de validation, c'est plus complexe. Ces derniers peuvent avoir 
> des règles de désérialisation complexes ce qui encouragerait à l'utilisation d'une désrialisation manuelle pour 
> des questions de sécurité comme sur le type PWHash par exemple.


5. Que pensez-vous de l’impact de l’utilisation de Casbin sur la performance de l’application ? sur
   l’efficacité du système de types ?
> L'évaluation des règles de Casbin introduit une surcharge à l'exécution et cette surcharge peut facilement se 
> transformer en goulot d'étranglement dans une applicaiton à fort traffic. L'utilisaiton de règles basées sur des 
> chaînes de charactères et l'évaluation dynamique signifient que nous perdons certaines garanties concernant la 
> logique d'autorisation. Cela peut créer une source d'erreurs et nous fait perdre les avantages d'un système à type 
> fort comme Rust.

6. Avez-vous d’autres remarques ?
> Casbin me semble être une solution avec des défauts critiques. Le fait que ce ne soit pas type-safe et que nous 
> devons accéder aux objets à travers les attributs dans un fichier csv n'est, à la fois, pas très pratique, mais 
> aussi peu intuitif.

