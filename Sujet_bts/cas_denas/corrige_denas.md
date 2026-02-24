# Corrigé détaillé — BTS SIO SLAM — U6 Cybersécurité des services informatiques — Cas Denas (Session 2022)

> **Date de correction** : 2026-02-24  
> **Objectif** : fournir une correction rédigée, structurée et détaillée (niveau attendu BTS).  

---

## Dossier A — Participation à l'atelier d'analyse de risque

### A1.1 — Évaluer les 4 critères (Confidentialité, Intégrité, Disponibilité, Preuve) pour les cas d'utilisation n°2 et n°6

> Référence : Document A2 (table des besoins). Les critères sont :
> - **Confidentialité** : pas de divulgation d'information
> - **Intégrité** : données exactes et non modifiées
> - **Disponibilité** : service accessible au moment voulu
> - **Preuve** : traçabilité opposable

#### Cas d'utilisation n°2 : « Un client consulte le catalogue des pièces »

- **Confidentialité : +**  
  Le catalogue de pièces (stock disponible, sites de stockage, prix, etc.) a une valeur commerciale et peut être sensible (concurrence, tension sur stock). Le besoin est important mais généralement moindre que pour une demande/commande.

- **Intégrité : ++**  
  Il est crucial que le client voie des informations fiables (disponibilité, prix, état), sinon on provoque des erreurs de commande, des litiges et une perte de confiance.

- **Disponibilité : ++**  
  Contexte aéronautique : une pièce de rechange est souvent urgente. Les clients doivent consulter le stock 24/7, sinon impact business important.

- **Preuve : 0 à +** (selon politique)  
  La simple consultation n'a pas toujours besoin d'être opposable. En revanche, il peut être utile de tracer des consultations anormales (extraction massive). On peut donc considérer **0** au sens « opposable » et **+** au sens « supervision sécurité ».

> Proposition d'évaluation "style sujet" : **Confidentialité : + ; Intégrité : ++ ; Disponibilité : ++ ; Preuve : +**.

#### Cas d'utilisation n°6 : « Le client confirme en signant électroniquement les documents »

- **Confidentialité : ++**  
  Les documents (contrat, docs techniques/admin) contiennent des données contractuelles, financières et potentiellement sensibles.

- **Intégrité : ++**  
  Le document signé ne doit pas être modifié : toute altération invaliderait l'engagement. L'intégrité est fondamentale.

- **Disponibilité : + à ++**  
  Le client doit pouvoir signer dans des délais compatibles (ex. 24h). Une indisponibilité peut bloquer la chaîne (réservation de stock, urgence). Selon le contexte, on peut mettre **++**.

- **Preuve : ++**  
  La signature électronique sert précisément à produire une preuve opposable : qui a signé, quoi, quand.

> Proposition d'évaluation : **Confidentialité : ++ ; Intégrité : ++ ; Disponibilité : ++ ; Preuve : ++**.

---

### A2.1 — Évaluer l'impact métier des événements redoutés n°4 et n°5

> Référence : Document A3.

#### Évènement redouté n°4
« Un client peu scrupuleux saisit et valide des demandes de pièces non compatibles avec l'aéronef déclaré en panne. »

- **Impact métier (proposition)** :
  - envoi/affectation de pièces inutiles ⇒ **perte de stock critique** et immobilisation de concurrents (cyber‑influence) ;
  - surcharge logistique (transport, retours), coûts directs ;
  - risque contractuel/légal si mauvaise pièce installée ;
  - dégradation de l'image (fiabilité/traçabilité).

=> Impact **très élevé** (cohérent avec la gravité ++ déjà indiquée).

#### Évènement redouté n°5
« Un attaquant accède aux données du PGI en utilisant de façon inappropriée l'interface d'une demande de pièce. »

- **Impact métier (proposition)** :
  - exposition de données sensibles (clients, facturation, stocks, commandes) ;
  - fraude (modification commandes/prix), sabotage ;
  - arrêt de production, rupture d'approvisionnement ;
  - conséquences réglementaires (secret industriel, RGPD si données personnelles) ;
  - impact potentiellement mondial sur la chaîne aéronautique.

=> Impact **très élevé** (gravité ++).

---

### A2.2 — Proposer 2 mesures pour les scénarios n°2 et n°5

> Référence : Document A4.

#### Scénario n°2 : attaque de mots de passe (brute force / dictionnaire)
Mesures possibles (2 attendues) :
1. **Limiter les tentatives et temporiser** :
   - verrouillage temporaire du compte après N échecs,
   - délai progressif (backoff),
   - CAPTCHA après plusieurs échecs.
2. **Renforcer l'authentification** :
   - politique de mot de passe (longueur, complexité),
   - MFA/2FA (OTP, push),
   - détection d'identifiants compromis.

(Autres mesures acceptables : rate limiting par IP, WAF, surveillance SIEM, listes de mots de passe interdits.)

#### Scénario n°5 : injection de code dans les demandes pour corrompre le PGI
Mesures possibles (2 attendues) :
1. **Validation stricte et encodage des données** :
   - validation côté serveur (whitelist),
   - rejet de caractères/structures non attendues,
   - encodage/échappement selon contexte (SQL/HTML/JSON/XML).
2. **Sécuriser l'interface d'échange PartEdge → API → PGI** :
   - requêtes préparées / ORM,
   - compte de service à privilèges minimaux,
   - filtrage applicatif + filtrage WAF,
   - segmentation réseau (DMZ),
   - journalisation/alerting sur payloads suspects.

---

### A2.3 — Expliquer les motivations des scénarios n°3 et n°4

- **Scénario 3** (demandes non validées) :
  - bloquer artificiellement des pièces rares ⇒ **cyber‑influence** sur la concurrence ;
  - perturber le marché (retards), obtenir un avantage commercial ;
  - tester le système / nuire à Denas.

- **Scénario 4** (demandes incompatibles) :
  - immobiliser des aéronefs concurrents en monopolisant des pièces ;
  - faire perdre du temps au service logistique ;
  - causer des surcoûts ;
  - provoquer des litiges.

---

## Dossier B — Amélioration de l'authentification

### B1.1 — Choisir la solution la plus sécurisée (AES vs SHA)

La solution la plus sécurisée est **le hachage** (solution 2), et plus précisément un hachage **adapté aux mots de passe** (bcrypt/argon2/scrypt).

Justification :
- un mot de passe **ne doit pas être déchiffrable** ;
- le chiffrement symétrique (AES) implique une **clé de déchiffrement** : si elle est compromise, tous les mots de passe le sont ;
- un hachage est **non réversible** (théoriquement) : on vérifie par comparaison (hash(mdp_saisi) == hash_stocké).

Attention : SHA seul est insuffisant (trop rapide). Il faut une fonction lente (bcrypt/argon2) + salage.

---

### B1.2 — Importance du salage (grain de sel)

Le **sel** est une valeur aléatoire ajoutée au mot de passe avant hachage.

Intérêt :
- empêche l'utilisation efficace des **tables arc‑en‑ciel** (rainbow tables) ;
- deux clients ayant le même mot de passe auront des **hash différents** ;
- rend les attaques par pré‑calcul beaucoup plus coûteuses.

Avec `password_hash()` en PHP (bcrypt), le sel est géré automatiquement et stocké dans le hash.

---

### B2.1 — Corriger readByLogin (requête préparée) pour éviter l'injection SQL

Code initial (ligne 6) concatène `$login` dans SQL ⇒ vulnérable.

Proposition de modification (lignes à modifier principalement 6 et 7) :

```php
// L6 (modifiée)
$req = "SELECT id, nom, login, pass, courriel, telephone, adresse, pays, estBloque, codePinOtp  
        FROM client WHERE login = :login";

// L7 (modifiée)
$prep = $connex->prepare($req);
$prep->bindValue(':login', $login, PDO::PARAM_STR);
$prep->execute();
$enreg = $prep->fetch(PDO::FETCH_OBJ);
```

Puis fermer le curseur sur `$prep`.

Lignes concernées (selon doc) :
- **L6** : remplacer la concaténation par un paramètre `:login`.
- **L7** : remplacer `query()` par `prepare()` + `bindValue()` + `execute()`.
- **L8** : `fetch()` sur `$prep` au lieu de `$res`.
- **L16** : `closeCursor()` sur `$prep`.

---

### B3.1 — Deux autres solutions 2FA (hors OTP boîtier)

Exemples :
1. **Application d'authentification TOTP** (Google Authenticator, FreeOTP, etc.).
2. **Notification push** (validation via app mobile) ou **WebAuthn/FIDO2** (clé physique).

(Acceptables aussi : SMS, email OTP — mais moins sécurisés.)

---

### B3.2 — Modifier loginView.php pour saisir l'OTP

On ajoute un champ `otp` (code à 6 chiffres) :

```html
<form method="post" action="/login/val" enctype="multipart/form-data">
  <label for="login">Login :</label><input type="text" id="login" name="login"/>
  <label for="pass">Mot de passe :</label><input type="password" id="pass" name="pass"/>
  <label for="otp">Code OTP :</label><input type="text" id="otp" name="otp" maxlength="6"/>
  <input type="submit" value="Valider">
</form>
```

On peut ajouter `inputmode="numeric"` et un contrôle côté client, mais l'essentiel est la saisie.

---

### B3.3 — Modifier LoginCtrl::verifLogin pour vérifier OTP + journaliser

Objectifs :
- vérifier login/pass (existant) ;
- si OK, vérifier OTP :
  - générer code attendu via classe `OTP` et `DateTime()` ;
  - comparer au code saisi ;
- écrire dans les logs via `syslog()` :
  - succès ⇒ `LOG_INFO` "Connexion client <id>" ;
  - échec login/pass ⇒ `LOG_WARNING` "Erreur connexion client <login>, cause : Erreur login/mot de passe" ;
  - échec OTP ⇒ `LOG_WARNING` "Erreur connexion client <login>, cause : Erreur OTP".

Insertion logique (sur le code du doc B3) :
- ajouter récupération `$otpForm` après lignes 9-10 ;
- après `password_verify(...)` et avant l'accueil, vérifier OTP ;
- ajouter appels syslog dans les branches.

Proposition (pseudo‑code PHP proche attendu) :

```php
$otpForm = filter_input(INPUT_POST, 'otp', FILTER_SANITIZE_STRING);

...
if($client == null){
    $erreur = true;
    syslog(LOG_WARNING, "Erreur connexion client $loginForm, cause : Erreur login/mot de passe");
}
else {
    if (password_verify($passForm, $client->getPass())) {
        // Vérification OTP
        $uneDateTime = new DateTime();
        $unOtp = new OTP($client);
        $codeAttendu = $unOtp->getCode($uneDateTime);

        if ((int)$otpForm === (int)$codeAttendu) {
            syslog(LOG_INFO, "Connexion client " . $client->getId());
            new AccueilView();
        } else {
            $erreur = true;
            syslog(LOG_WARNING, "Erreur connexion client $loginForm, cause : Erreur OTP");
        }
    } else {
        $erreur = true;
        syslog(LOG_WARNING, "Erreur connexion client $loginForm, cause : Erreur login/mot de passe");
    }
}
```

Lignes où insérer (doc B3) :
- après **L10** : lecture `otp`.
- dans la branche succès de **password_verify** (autour de L19–21) : vérification OTP + `syslog(LOG_INFO, ...)`.
- dans les échecs : ajouter `syslog(LOG_WARNING, ...)`.

---

## Dossier C — Validation des demandes client

### C1.1 — Condition pour que l'échange électronique soit recevable juridiquement

Condition essentielle : utiliser une **signature électronique qualifiée** (ou au minimum une signature électronique répondant aux exigences légales eIDAS), garantissant :
- identification du signataire,
- lien univoque signature ↔ document,
- intégrité du document,
- preuve de consentement.

En pratique : passer par un **prestataire de confiance** et un dispositif conforme (horodatage, certificat, etc.).

---

### C1.2 — Solutions techniques pour les 4 exigences

1. **Confidentialité totale** :
   - chiffrement de bout en bout / canal sécurisé (TLS) + chiffrement du contenu (S/MIME, PGP) ou portail sécurisé.

2. **Authenticité + non‑modification** :
   - signature numérique du document (certificat),
   - empreinte (hash) + signature,
   - horodatage.

3. **Preuve de réception** :
   - accusé de réception électronique qualifié,
   - service d'envoi recommandé électronique (LRE),
   - dépôt/consultation sur un portail avec journal opposable.

4. **Signature client engageante** :
   - signature électronique (avancée/qualifiée),
   - vérification identité (KYC),
   - certificat ou mécanisme conforme eIDAS.

---

### C2.1 — Requête clients avec demandes >24h non confirmées

Demande abusive = demande non confirmée dans les 24h : `dateConfirmation` null (ou vide) et `dateDemande <= NOW() - INTERVAL 24 HOUR`.

On veut pour chaque client : id, nom, nombre total de pièces demandées (ici : nombre de demandes abusives, ou somme de `numPiece` si champ représente quantité ; le schéma montre `numPiece` comme FK vers `Piece.numSerie` et donc pas une quantité. On interprète donc "nombre total de pièces demandées" = nombre de demandes, car 1 demande = 1 pièce affectée.)

```sql
SELECT c.id, c.nom, COUNT(d.id) AS nbPiecesDemandees
FROM Client c
JOIN Demande d ON d.idClient = c.id
WHERE d.dateConfirmation IS NULL
  AND d.dateDemande <= (NOW() - INTERVAL 24 HOUR)
GROUP BY c.id, c.nom;
```

---

### C2.2 — Trigger : bloquer client si nb_abus(idClient) == 2 et empêcher insertion

Déclencheur **BEFORE INSERT** sur `Demande` :
- calculer nb abus du client ;
- si = 2 : mettre `Client.estBloque = true` ;
- empêcher insertion : en MySQL on peut utiliser `SIGNAL SQLSTATE '45000'`.

Proposition (MySQL) :

```sql
CREATE TRIGGER verif_abus_demande
BEFORE INSERT ON Demande
FOR EACH ROW
BEGIN
  DECLARE nb INT;

  SET nb = nb_abus(NEW.idClient);

  IF nb = 2 THEN
    UPDATE Client
      SET estBloque = true
    WHERE id = NEW.idClient;

    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'Client bloque : trop de demandes abusives';
  END IF;
END;
```

---

### C2.3 — Adapter la modélisation : compatibilité TypePiece ↔ ModeleAeronef + commentaire

Un type de pièce peut être compatible avec plusieurs modèles, et un modèle avec plusieurs types ⇒ relation **N:N**.

On ajoute :
- entité/table `ModeleAeronef` (si elle n'existe pas) : `(id, libelle)` ou utiliser la chaîne `modeleAeronef` si on ne normalise pas.
- table d'association `Compatibilite` :

```
Compatibilite(idTypePiece, modeleAeronef, commentaire)
PK (idTypePiece, modeleAeronef)
FK idTypePiece -> TypePiece(id)
```

Ou version normalisée :

```
ModeleAeronef(id, libelle)
Compatibilite(idTypePiece, idModeleAeronef, commentaire)
```

---

### C2.4 — Proposer une solution pour implémenter la contrainte (sans coder)

Solutions possibles :
1. **Contrôle applicatif côté serveur** avant insertion :
   - lors de la saisie, vérifier l'existence d'une compatibilité dans la table `Compatibilite`.

2. **Contrainte au niveau SGBD** (si modèle normalisé) :
   - trigger BEFORE INSERT/UPDATE sur `Demande` qui vérifie la compatibilité via requête, sinon refuse (`SIGNAL`).

Choix recommandé : double contrôle (UI + serveur + DB) ; au minimum contrôle serveur.

---

## Dossier D — Envoi des données au PGI (API REST)

### D1.1 — Ajouter la méthode POST dans DemandeRest

Objectif : appeler `DemandeService.create(...)` et retourner :
- **201 CREATED** si OK (ou 200),
- **400 BAD_REQUEST** si échec.

Proposition :

```java
@POST
@Consumes(MediaType.APPLICATION_JSON)
public Response createDemande(DemandeJson laDemandeJson)
{
    boolean ret = DemandeService.create(laDemandeJson);
    if (ret) {
        return Response.status(Status.CREATED).build();
    } else {
        return Response.status(Status.BAD_REQUEST).build();
    }
}
```

---

### D2.1 — Vérifications par regex + contrôle supplémentaire

#### a) Compléter verifDonneesCreate

Contrôles demandés :
- modeTransport ∈ {INTERNE, EXTERNE}
- typeEchange ∈ {STANDARD, SILVER, GOLD}
- dateDemande format ISO YYYY-MM-DD

La regex date correcte : `^[0-9]{4}-[0-9]{2}-[0-9]{2}$`.

Dans le sujet, l'expression est mal typée (`[0-9]4` au lieu de `{4}`). On corrige.

Proposition :

```java
if (Pattern.matches("^[0-9]{4}-[0-9]{2}-[0-9]{2}$", laDem.getDateDemande()) == false) {
    res = false;
}
if (Pattern.matches("INTERNE|EXTERNE", laDem.getModeTransport()) == false) {
    res = false;
}
if (Pattern.matches("STANDARD|SILVER|GOLD", laDem.getTypeEchange()) == false) {
    res = false;
}
```

#### b) Contrôle supplémentaire sur la date

Exemples :
- vérifier que la date est **réellement valide** (pas 2022-02-33) via parsing strict ;
- vérifier que la date n'est pas dans le futur (ou trop ancienne) ;
- utiliser `dateFormat.setLenient(false)`.

---

### D2.2 — Compléter le test unitaire manquant (non-régression)

On a déjà des tests pour :
- mode transport invalide (dem1, "PERSO")
- type échange invalide (dem2, "AUTRE")
- date invalide (dem3, "2022-03-33")

Test manquant logique : **demande valide** ⇒ `true`.

Il faut ajouter dans `setUp()` une demande valide (dem4), puis test :

```java
private DemandeJson dem4;

@Before
public void setUp(){
   ...
   this.dem4 = new DemandeJson(4, "2022-03-22", " ", "STANDARD", 0,
       "INTERNE", 44, "A320", 2, 3, null);
}

@Test
public void testCreateValide(){
   boolean result = DemandeService.create(dem4);
   assertEquals("Create avec demande valide", true, result);
}
```

> Remarque : si `DemandeService.create` appelle réellement la BDD via DaoDemande, un vrai test unitaire doit mocker DaoDemande. Dans le cadre du sujet, on attend surtout la validation des données.