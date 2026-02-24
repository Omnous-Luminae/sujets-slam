# Corrigé détaillé — BTS SIO SLAM — U7 Cybersécurité des services informatiques — Cas Kirassur (Session 2025)

> **Date de correction** : 2026-02-24  
> **Remarque** : les réponses sont rédigées de façon *détaillée* (explications + justification + extraits de code SQL/PHP).  

---

## Dossier A — Prise en compte d’évènements redoutés

### Mission A1 — Contrer l’évènement redouté

#### A1.1 — Justifier le choix d’un déclencheur (trigger)

Le choix d’implémenter la règle au niveau **base de données** via un **trigger** est pertinent pour plusieurs raisons :

1. **Centralisation de la règle métier critique**  
   La règle « trop de sinistres *Bris de glace* sur une période ⇒ nouveau sinistre *à vérifier* » est une règle de sécurité/anti‑fraude. En la plaçant dans le SGBD, elle s’applique **quel que soit le point d’entrée** (application Web, script d’import, outil interne, API, etc.).

2. **Intégrité et cohérence des données**  
   Le trigger garantit que la colonne `aVerifier` est positionnée correctement **au moment même de l’insertion**, donc on évite les oublis, les erreurs de développement ou les insertions « directes » qui contourneraient une vérification applicative.

3. **Réduction de la surface d’attaque**  
   Si le contrôle était uniquement dans le code applicatif, il suffirait qu’un autre programme (ou un attaquant ayant obtenu un accès SQL) insère des sinistres sans passer par ce code. Avec le trigger, la règle est imposée par le SGBD.

4. **Maintenance et auditabilité**  
   Une règle critique dans la base est plus simple à auditer : un DBA/RSI peut vérifier l’existence du trigger et son code. Cela limite la dispersion de la logique dans plusieurs modules applicatifs.

Limite à connaître (à citer éventuellement) : un trigger complexifie parfois le débogage et peut avoir un impact performance si mal écrit, mais ici la règle est simple et ciblée.

---

#### A1.2 — Compléter le trigger

##### a) Expliquer la requête lignes 15 à 20

```sql
SELECT count(*) into nbSinDeclare
FROM Sinistre
JOIN Garantie ON Garantie.id = Sinistre.idGarantie
WHERE Sinistre.idContrat = NEW.idContrat
  AND libelle = "Bris de glace"
  AND dateSinistre >= dateDebPeriode
  AND dateSinistre <= NEW.dateSinistre;
```

Cette requête :

- **compte** (`count(*)`) le nombre de sinistres déjà enregistrés dans la table `Sinistre` ;
- **pour le même contrat** que le sinistre en cours d’insertion (`Sinistre.idContrat = NEW.idContrat`) ;
- **de garantie “Bris de glace”** (via la jointure avec `Garantie` et le filtre `libelle = "Bris de glace"`) ;
- **dont la date du sinistre** (`dateSinistre`) se situe **dans la période de référence** :
  - entre `dateDebPeriode` (calculée ligne 13 avec `SUBDATE`) ;
  - et la date du sinistre en cours (`NEW.dateSinistre`).

Le résultat (un entier) est stocké dans la variable `nbSinDeclare`.

##### b) Code à ajouter (lignes 22-23) pour mettre `aVerifier` à “O”

On compare le nombre trouvé au maximum autorisé (`nbMaxSinistres`). Si le seuil est dépassé, on force l’attribut.

```sql
IF nbSinDeclare > nbMaxSinistres THEN
   SET NEW.aVerifier = 'O';
ELSE
   SET NEW.aVerifier = 'N';
END IF;
```

> On met aussi explicitement `N` sinon, pour éviter une valeur NULL si l’application n’a rien fourni.

##### c) Modifier le trigger pour que le contrôle ne s’applique qu’à “Bris de glace”

Le trigger actuel filtre déjà sur `libelle = "Bris de glace"` dans la requête de comptage, mais le **traitement** (mise à vérifier) doit être exécuté **uniquement** si la garantie du sinistre en cours est bien “Bris de glace”.

On utilise la variable `libelleGarantie` (chargée lignes 9–11) :

```sql
IF libelleGarantie = 'Bris de glace' THEN
   -- calcul + comptage + comparaison
END IF;
```

**Lignes concernées** (dans le document A1 fourni) :
- ajout d’un `IF` après la ligne **11** (ou juste avant le calcul ligne 12/13),
- ajout du `END IF` avant la ligne **24**,
- et le traitement de comparaison (lignes **22–23**) doit être placé **dans** ce bloc conditionnel.

##### Trigger complet (proposition)

```sql
CREATE TRIGGER controleSinistre
BEFORE INSERT ON Sinistre FOR EACH ROW
BEGIN
  DECLARE nbSinDeclare int;
  DECLARE dateDebPeriode datetime;
  DECLARE nbJours int;
  DECLARE nbMaxSinistres int;
  DECLARE libelleGarantie varchar(100);

  -- Récupération des paramètres de la garantie
  SELECT libelle, nbMaxSinistresPeriode, nbJoursPeriode
    INTO libelleGarantie, nbMaxSinistres, nbJours
  FROM Garantie
  WHERE id = NEW.idGarantie;

  -- Contrôle uniquement pour "Bris de glace"
  IF libelleGarantie = 'Bris de glace' THEN

    -- début de période
    SET dateDebPeriode = SUBDATE(NEW.dateSinistre, INTERVAL nbJours DAY);

    -- nombre de sinistres sur la période
    SELECT count(*) INTO nbSinDeclare
    FROM Sinistre
    WHERE Sinistre.idContrat = NEW.idContrat
      AND Sinistre.idGarantie = NEW.idGarantie
      AND dateSinistre >= dateDebPeriode
      AND dateSinistre <= NEW.dateSinistre;

    -- si dépassement : à vérifier
    IF nbSinDeclare > nbMaxSinistres THEN
      SET NEW.aVerifier = 'O';
    ELSE
      SET NEW.aVerifier = 'N';
    END IF;

  END IF;
END;
```

> Variante : conserver la jointure avec Garantie. Ici on simplifie en utilisant `Sinistre.idGarantie = NEW.idGarantie` puisque la garantie est déjà connue.

---

### Mission A2 — Détecter l’évènement suspect

#### A2.1 — Modifier la requête de la liste des sinistres

Attendus :
1. n’afficher **que** les sinistres « Bris de glace » ;
2. afficher **d’abord** ceux à vérifier (`aVerifier='O'`) ;
3. garder ensuite un tri cohérent (par date de déclaration croissante) ;
4. afficher le **nom de l’assuré**.

Requête corrigée :

```sql
SELECT
    Contrat.id AS idContrat,
    Assure.nom AS nomAssure,
    Assure.prenom AS prenomAssure,
    Sinistre.numero,
    Sinistre.description,
    Sinistre.dateSinistre,
    Sinistre.dateDeclaration,
    Sinistre.dateEnregistrement,
    Garantie.libelle,
    Sinistre.aVerifier
FROM Contrat
INNER JOIN Sinistre   ON Contrat.id = Sinistre.idContrat
INNER JOIN Garantie   ON Garantie.id = Sinistre.idGarantie
INNER JOIN Assure     ON Assure.id = Contrat.idAssure
WHERE Sinistre.dateReglement IS NULL
  AND Sinistre.idGestionnaire = :idGestionnaireConnecte
  AND Garantie.libelle = 'Bris de glace'
ORDER BY
  CASE WHEN Sinistre.aVerifier = 'O' THEN 0 ELSE 1 END,
  Sinistre.dateDeclaration ASC;
```

Explications :
- la jointure `Assure` permet d’afficher `nom/prenom` ;
- le `CASE` dans le `ORDER BY` force le tri avec **"à vérifier" en premier** ;
- on conserve ensuite la date de déclaration pour l’ordre de traitement.

---

## Dossier B — Ouverture du SI aux partenaires extérieurs

### Mission B1 — Étude des échanges

#### B1.1 — Justifier HTTPS

##### a) Évènement redouté avec HTTP

Avec **HTTP**, les échanges transitent **en clair** sur le réseau :
- la clé API (`cleAPI`) et/ou le token (`token`) présents dans l’URL ;
- les réponses (dont le token retourné par `die($token)`) ;
- et potentiellement des données personnelles si des pages retournent des informations de contrat.

Évènements redoutés typiques :
- **interception (sniffing)** : un attaquant sur le même réseau (Wi‑Fi public, FAI compromis, proxy, etc.) lit la clé API et/ou le token ;
- **attaque de l’homme du milieu (MITM)** : modification de requêtes/réponses (ex : remplacement d’un idContrat) ;
- **usurpation** : réutilisation des identifiants interceptés pour accéder aux contrats.

##### b) Comment HTTPS protège

HTTPS = HTTP + **TLS**. TLS apporte :
- **confidentialité** : chiffrement des données ⇒ un sniffing ne révèle pas la clé API ni le token ;
- **intégrité** : détection des modifications en transit ;
- **authentification du serveur** (certificat) : le client peut vérifier qu’il parle bien à `www.KIRASSUR.com` et pas à un faux serveur.

---

#### B1.2 — Pourquoi ne pas renvoyer la clé API au navigateur de l’assuré

Même sous HTTPS, exposer la clé API au navigateur (donc à l’assuré) est dangereux car :

- **la clé API identifie/autorise la société partenaire**, pas l’assuré ;
- côté client, la clé peut être :
  - vue dans le code source, les outils développeur, l’historique, les favoris ;
  - enregistrée dans des logs (proxy, navigateur, extensions) ;
  - récupérée via XSS/compromission du poste.

Conséquence : l’assuré (ou un attaquant) pourrait réutiliser la clé API pour appeler l’API en se faisant passer pour le partenaire, ce qui casse la séparation des rôles.

Le bon modèle est :
- le partenaire appelle l’API avec sa clé côté serveur ;
- l’assuré reçoit **un token temporaire** limité, idéalement associé à *son* contrat et à un usage.

---

#### B1.3 — Les jetons en base donnent-ils accès à des données personnelles ?

Oui, **indirectement**.

Un jeton (`Jeton.valeur`) n’est pas une donnée personnelle « en clair » comme un nom/prénom, mais :
- il est lié à `idContrat` ;
- `idContrat` est lié à un assuré (`Contrat.idAssure`) ;
- donc en pratique, posséder un jeton valide permet d’accéder aux informations d’un contrat, donc à des **données à caractère personnel** (identité, coordonnées, informations contractuelles, sinistres, etc.).

Au sens RGPD, c’est un **identifiant** permettant d’accéder à des données personnelles :
- il doit être protégé (confidentialité, durée limitée, non prévisible, stockage sécurisé, accès restreint en BDD).

---

#### B1.4 — Bonne pratique respectée dans tokenEnregistrer mais pas dans tokenCharger

Bonne pratique : **requêtes préparées / paramètres bindés** pour éviter l’injection SQL.

- `tokenEnregistrer()` utilise `prepare()` + `bindParam()` pour `:param1`, `:param2`, `:param3` (même si la date est injectée en chaîne — point améliorable).
- `tokenCharger()` **n’utilise pas** de paramètre bindé :

```php
FROM Jeton WHERE valeur = '$token_val'
```

Cela ouvre la porte à une **injection SQL** si un attaquant contrôle `token` dans l’URL.

Correction attendue (sans tout recoder) :
- remplacer par `WHERE valeur = :param1` puis `bindParam`.

---

#### B1.5 — Limiter la validité du token

##### a) Justifier le contrôle de durée de validité

Limiter la durée réduit :
- le risque de **rejeu** (token volé utilisable indéfiniment) ;
- l’impact d’une fuite de logs/historique navigateur ;
- la fenêtre d’attaque en cas de compromission du terminal.

C’est un principe de sécurité : **minimisation** et **réduction de l’exposition temporelle**.

##### b) Identifier les instructions + table/champ

Dans `DAO::tokenEnregistrer()` :
- calcul de la date limite :
  - ligne 41 : création date courante `$dateHeureFin = date_create(...)` ;
  - lignes 42–43 : `date_add(... $dureeEnSec . ' seconds')` ;
  - ligne 45 : formatage `$dateHeureFinBdd = date_format(...);`
- stockage :
  - table **`Jeton`**
  - champ **`dateHeureLimite`** (cf. doc B8)

---

### Mission B2 — Accès illicite à des données

#### B2.1 — Vérifier l’accès illégitime et expliquer quoi faire

À la lecture des journaux (doc B10), l’IP `192.0.2.3` :
- appelle `index.php?cleAPI=...&idContrat=10001` ⇒ obtient un token ;
- puis appelle `index.php?token=...` ⇒ accès OK (200) ;
- et répète en incrémentant `idContrat` jusqu’à `10162`.

Dans le prototype, l’API `obtenirTokenContrat.php` :
- vérifie seulement que `cleAPI` est valide (`cleAPIVerifierValidite`) ;
- **ne vérifie pas** que le `idContrat` demandé appartient au partenaire détenteur de cette clé API.

Donc **oui**, le code permet un accès illégitime si l’attaquant a une clé API partenaire valide (ou l’a volée) : iel peut demander des tokens pour des contrats qui ne sont pas gérés par ce partenaire.

Pour éviter (sans coder) :
- lier la clé API à l’identité du partenaire (`Partenaire.id`) ;
- lors d’une demande de token, vérifier en base que :

```text
Contrat.id = idContrat demandé
ET Contrat.idPartenaire = partenaire correspondant à la cleAPI
```

Si ce n’est pas le cas : refuser (403/404) et ne pas générer de token.

Mesures complémentaires :
- journaliser les tentatives ;
- mettre en place rate limiting ;
- prévoir détection d’énumération (IDOR).

---

#### B2.2 — Moyen réseau pour invalider une IP externe anormale

Exemples acceptables :
- ajouter une règle de pare‑feu (iptables/nftables/Firewall cloud) pour **bloquer l’IP** (DROP/REJECT) ;
- configurer un WAF / reverse proxy (ex : fail2ban, mod_security) pour bannir l’IP ;
- blacklisting sur un équipement de sécurité (FW/IDS/IPS).

Réponse type : **blocage au pare-feu** ou **fail2ban** basé sur les logs HTTP.

---

#### B2.3 — Obligations RGPD après violation de données personnelles

En cas de violation (accès non autorisé à des contrats) :

1. **Notifier la CNIL** (autorité de contrôle) **dans les 72 heures** après en avoir eu connaissance, sauf si la violation est peu susceptible d’engendrer un risque pour les droits et libertés.
2. **Informer les personnes concernées** (assurés) si la violation est susceptible d’engendrer un **risque élevé** (ex : exposition de données sensibles, fraude possible), en décrivant :
   - la nature de la violation,
   - les mesures prises,
   - les recommandations.
3. **Documenter l’incident** en interne (registre des violations) : faits, impacts, mesures correctives (obligation d’accountability).
4. Mettre en œuvre des **mesures correctives** (techniques et organisationnelles) pour éviter la récidive.

---

## Dossier C — Journalisation des accès et gestion des alertes

### Mission C1 — Journalisation des actions sensibles

#### C1.1 a) Compléter `logAction` (ActionManager)

Objectif : produire une ligne au format (doc C5) :

```
Date heure - adresse IP - login - libellé action
```

On utilise :
- l’horodatage via `$_SERVER['REQUEST_TIME']` (comme `logSQL`) ;
- l’IP client via `$_SERVER['REMOTE_ADDR']` ;
- `$loginUtil` et `$uneAction->getLibelle()` (ou attribut selon classe Action).

Proposition de code :

```php
public function logAction(string $loginUtil, Action $uneAction)
{
    $horodatage = date('Y-m-d H:i:s', $_SERVER['REQUEST_TIME']);
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'IP inconnue';

    // On journalise le libellé (action métier), pas l’étiquette UI
    $ligne = $horodatage . " - " . $ip . " - " . $loginUtil . " - " . $uneAction->getLibelle();

    $this->fichierLogActions->ajouterLog($ligne);
}
```

> Remarque : selon l’implémentation de `Action`, la méthode peut s’appeler `getLibelle()` / `getEtiquette()` ; l’attendu est de journaliser un libellé compréhensible.

---

#### C1.1 b) Compléter `enregistrerActionSensible` (contrôleur)

Objectif :
- déterminer le login :
  - si utilisateur connecté ⇒ son login ;
  - sinon ⇒ `non connecté` ;
- vérifier si l’action est sensible (`estSensible == true`) ;
- si oui, appeler `ActionManager::logAction(login, action)`.

Proposition :

```php
function enregistrerActionSensible(Action $uneAction)
{
    $connexionManager = new ConnexionManager();
    $utilisateurConnecte = $connexionManager->getUtilisateurConnecte();

    $login = 'non connecté';
    if ($utilisateurConnecte != null) {
        $login = $utilisateurConnecte->getLogin();
    }

    $actionManager = new ActionManager();

    // Selon le modèle : estSensible booléen ou '0/1'
    if ($uneAction->getEstSensible()) {
        $actionManager->logAction($login, $uneAction);
    }
}
```

---

### Mission C2 — Modélisation d’un système d’alerte + habilitations

#### C2.1 — Finaliser la schématisation des données (proposition)

Objectifs à couvrir :
1. utilisateurs (gestionnaires, responsables) avec relation hiérarchique ;
2. actions (avec sensibilité) + paramètres de supervision (intervalle + seuil) ;
3. profils contenant un ensemble d’actions ;
4. attribution d’un profil à un utilisateur sur une période (sans historisation) ;
5. habilitations unitaires ponctuelles sur une période (sans historisation) ;
6. journaliser chaque occurrence d’action sensible (id + horodatage) ;
7. gérer les alertes (état, affectation responsable, date/heure).

##### a) Schéma relationnel (texte)

**Utilisateur**(id, nom, prenom, login, motDePasseHash, type, idResponsable)
- `type` ∈ {gestionnaire, responsable}
- `idResponsable` FK -> Utilisateur.id (nullable pour un responsable)

**Action**(id, libelle, etiquette, estSensible, nbJoursSurveillance, nbMaxOccurrences)
- `nbJoursSurveillance` et `nbMaxOccurrences` utiles seulement si `estSensible = 1`

**Profil**(id, libelle)

**ProfilAction**(idProfil, idAction)
- PK(idProfil, idAction)
- FK -> Profil.id / Action.id

**AttributionProfil**(idUtilisateur, idProfil, dateDebut, dateFin)
- PK(idUtilisateur) ou PK(idUtilisateur, idProfil) selon règle « 1 profil à la fois ? »
- (Sans historisation : une nouvelle attribution peut écraser l’ancienne)

**HabilitationUnitaire**(idUtilisateur, idAction, dateDebut, dateFin)
- PK(idUtilisateur, idAction)
- (Sans historisation : reconduction écrase)

**ActionSensibleJournal**(id, idUtilisateur, idAction, dateHeure)
- PK(id)
- FK -> Utilisateur.id / Action.id

**Alerte**(id, idUtilisateur, idAction, dateHeureDeclenchement, etat, idResponsableAffecte, dateHeureAffectation)
- `etat` ∈ {nouvelle, affectee, resolue, classee}
- `idResponsableAffecte` FK -> Utilisateur.id (nullable)

##### b) Associations (E/A)

- Un **Profil** *contient* plusieurs **Action** (N:N via ProfilAction)
- Un **Utilisateur** *reçoit* un **Profil** (N:N dans le temps, mais sans historisation ⇒ table AttributionProfil)
- Un **Utilisateur** *reçoit* des **habilitations unitaires** sur des **Action** (N:N via HabilitationUnitaire)
- Une **Action sensible** exécutée génère une **entrée de journal** (1 occurrence = 1 ligne)
- Une **Alerte** concerne (Utilisateur, Action) et peut être *affectée* à un responsable.

##### c) Remarques de conception / cybersécurité

- Stocker `motDePasseHash` (hash fort type bcrypt/argon2), jamais en clair.
- `ActionSensibleJournal` + `Alerte` servent d’outils d’audit et de détection d’abus.
- Les seuils dans Action (intervalle/seuil) permettent un déclenchement homogène côté application.

---

## Annexes — Points de vigilance (bonus)

- **Ne jamais mettre secrets dans l’URL** si possible : préférer en-têtes (`Authorization: Bearer ...`) ou POST ; l’URL se retrouve dans historique/logs.
- Mettre en place :
  - rotation/révocation des clés API ;
  - rate limiting anti-énumération ;
  - surveillance SIEM / alerting.