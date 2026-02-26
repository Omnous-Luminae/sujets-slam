# Correction – BTS SIO Option SLAM · Session 2022
## U6 – Cybersécurité des services informatiques
### Cas Easy2Drive

---

## DOSSIER A – Sécurisation de l'application de formation en ligne (e-learning)

---

### Question A.1.1 – Analyse des niveaux de sécurité des récits utilisateurs

#### a) Différence de disponibilité entre récits 1 et 2

- **Récit 1** (consultation publique sans compte) : disponibilité **importante (\*\*)** car la famille doit pouvoir accéder au site à tout moment pour s'informer. Il s'agit d'une vitrine commerciale dont l'indisponibilité nuirait à l'image de l'entreprise et ferait perdre des clients potentiels.
- **Récit 2** (modification du mot de passe) : disponibilité **modérée (\*)** car si la fonctionnalité est temporairement indisponible, l'élève peut simplement attendre avant de changer son mot de passe. Cela ne bloque pas immédiatement son accès à la formation.

#### b) Niveaux d'intégrité et confidentialité du récit 2

- **Intégrité importante (\*\*)** : le mot de passe est un élément critique de sécurité. S'il était corrompu ou modifié à l'insu de l'élève, cela bloquerait son accès ou permettrait une usurpation d'identité. Il est essentiel que la modification soit exacte et effective.
- **Confidentialité importante (\*\*)** : le mot de passe est une donnée secrète par nature. Sa divulgation permettrait à un tiers de se connecter au compte de l'élève et d'accéder à ses données personnelles et à sa formation.

#### c) Différence de niveau de preuve entre récits 1 et 3

- **Récit 1** (consultation publique) : preuve **sans objet (-)** car aucun compte n'est créé, aucune donnée personnelle n'est déposée, et aucune action engageante n'est réalisée. Il n'y a donc rien à prouver en cas de contestation.
- **Récit 3** (poster un avis) : preuve **importante (\*\*)** car l'élève publie un contenu textuel potentiellement litigieux (diffamation, faux avis). En cas de contentieux, il doit être possible de prouver qui a posté quel avis, à quelle date, depuis quel compte. Les traces constituent une preuve opposable.

---

### Question A.2.1 – Non-conformité de la gestion des cookies

En analysant le Document A2 (bandeau cookie actuel) et le Document CNIL 2 :

Le bandeau actuel affiche uniquement un bouton « ✓ Accepter les cookies » sans proposer de bouton **Refuser** ni d'option de **gestion personnalisée**. Il se contente d'indiquer l'usage des cookies sans permettre un choix libre et éclairé.

Depuis la délibération de la CNIL du **17 septembre 2020**, le consentement implicite n'est plus accepté. L'utilisateur doit pouvoir **accepter, refuser ou gérer** les cookies de façon claire et explicite. Le refus doit être aussi simple que l'acceptation.

**Non-conformités identifiées :**
- Absence d'un bouton « Refuser les cookies ».
- Absence d'une option « Gérer les cookies » (paramétrage granulaire).
- Le consentement est présenté comme acquis par défaut (seul « Accepter » est proposé).

---

### Question A.2.2 – Données à caractère personnel dans le récit utilisateur n°1

D'après le Document A3 (politique de confidentialité), lors d'une simple consultation du site sans création de compte, les données suivantes sont collectées automatiquement :

| Donnée collectée | Caractère personnel ? | Justification |
|---|---|---|
| Adresse IP | **Oui** | Permet d'identifier indirectement un internaute ou son foyer ; reconnue comme donnée personnelle par la CNIL. |
| Type d'appareil | Non (seul) | Information technique générique ne permettant pas d'identifier une personne. |
| Teneur des requêtes | Dépend | Peut devenir personnelle si combinée à l'IP (révèle les centres d'intérêt). |
| Version du navigateur | Non (seul) | Donnée technique générique. |
| Résolution de l'écran | Non (seul) | Donnée technique générique. |
| Système d'exploitation / langue | Non (seul) | Donnée technique générique. |

**Seule l'adresse IP est clairement une donnée à caractère personnel** dans ce contexte, car elle permet d'identifier indirectement l'utilisateur ou son terminal. La combinaison de plusieurs données techniques (fingerprinting) pourrait également constituer une donnée personnelle, mais chaque donnée prise isolément ne suffit généralement pas.

---

### Question A.3.1 – Problèmes du mot de passe initial

#### a) Non-conformités sécuritaires du mot de passe initial

En analysant le Document A4 (courriel de confirmation) :

- **Envoi en clair par courriel** : le mot de passe `qamQdVD3` est transmis en texte clair dans un courriel. Si la messagerie est interceptée (attaque de type man-in-the-middle, courriel mal acheminé, accès à la boîte mail), le mot de passe est directement lisible par un tiers.
- **Absence de changement obligatoire** : l'élève peut conserver ce mot de passe initial « tout au long de sa formation ». Or ce mot de passe a été généré par l'auto-école et potentiellement connu de plusieurs personnes.
- **Connaissance du mot de passe par un tiers** : l'auto-école qui crée le compte connaît (ou peut connaître) le mot de passe initial, ce qui viole le principe de confidentialité exclusive.

#### b) Meilleure solution pour communiquer le mot de passe initial

La solution recommandée est de **ne jamais envoyer de mot de passe** dans un courriel. À la place :

1. L'auto-école crée le compte et un **lien de première connexion à usage unique et limité dans le temps** est envoyé à l'élève par courriel.
2. Lors de sa première connexion via ce lien, l'élève est **obligé de définir lui-même son propre mot de passe** (qui ne sera donc jamais connu d'un tiers).
3. Le lien expire après utilisation ou après un délai court (ex. 24h).

---

### Question A.3.2 – Amélioration de la fonction `verifPassword`

#### a) Politique de mot de passe actuelle

En analysant le code de `verifPassword` (Document A5) :

- **Longueur minimale** : 8 caractères (ligne 5 : `if ($longueur >= 8) { $points_long = 1; }`)
- **Complexité** :
  - Au moins une minuscule → +1 point
  - Au moins une majuscule → +2 points
  - Au moins un chiffre → +3 points
- **Score requis** : `$points_long * $points_comp == 6`

Pour obtenir exactement 6 : longueur ≥ 8 (× 1) et complexité = 6 → minuscule (1) + majuscule (2) + chiffre (3) = 6. Donc le mot de passe doit contenir au moins **8 caractères avec minuscule, majuscule et chiffre**.

**Il n'y a pas de vérification de caractère spécial** dans la version actuelle.

#### b) Modifications pour respecter les recommandations CNIL

D'après le Document CNIL 1, la CNIL exige :
- Longueur **≥ 12 caractères** (au lieu de 8)
- Au moins une minuscule (+1 pt)
- Au moins une majuscule (+2 pts)
- Au moins un chiffre (+3 pts)
- Au moins un caractère spécial (+4 pts)
- Score requis **≥ 10**

**Lignes à modifier ou ajouter :**

```php
// Ligne 1 modifiée : le seuil passe à 10
$points_total = 10;

// Ligne 5 modifiée : longueur minimale passe à 12
if ($longueur >= 12) { $points_long = 1; }

// Ligne à ajouter après la ligne 8 : ajout du critère caractère spécial
if (preg_match("/\W/", $mdp)) { $points_comp = $points_comp + 4; }

// Ligne 10 modifiée : comparaison >= au lieu de ==
return ($points_total <= $resultat);
```

**Code modifié complet de la fonction :**

```php
function verifPassword($mdp): bool
{
    $points_total = 10;                          // modifié (était 6)
    $longueur = strlen($mdp);
    $points_long = 0;
    $points_comp = 0;
    if ($longueur >= 12) { $points_long = 1; }   // modifié (était 8)
    if (preg_match("/[a-z]/", $mdp)) { $points_comp = $points_comp + 1; }
    if (preg_match("/[A-Z]/", $mdp)) { $points_comp = $points_comp + 2; }
    if (preg_match("/[0-9]/", $mdp)) { $points_comp = $points_comp + 3; }
    if (preg_match("/\W/",    $mdp)) { $points_comp = $points_comp + 4; } // ajouté
    $resultat = $points_long * $points_comp;
    return ($points_total <= $resultat);         // modifié (était ==)
}
```

#### c) Modification de la fonction de tests unitaires `testVerifPassword`

Les anciens tests doivent être mis à jour pour refléter la nouvelle politique (≥ 12 caractères, caractère spécial obligatoire, score ≥ 10) :

```php
public function testVerifPassword()
{
    // Trop court (< 12 caractères) → false
    $this->assertSame(false, verifPassword("Qam3!"));

    // 12 caractères mais sans caractère spécial → score = 1*(1+2+3) = 6 < 10 → false
    $this->assertSame(false, verifPassword("qamQdVDbdAb3"));

    // 12 caractères, minuscules seulement (pas de maj, chiffre, spécial) → false
    $this->assertSame(false, verifPassword("qamqdvdbdabc"));

    // 12 caractères, avec majuscule et chiffre mais sans spécial → score = 1*(1+2+3) = 6 < 10 → false
    $this->assertSame(false, verifPassword("qamQdVDbabc3"));

    // Ancien mot de passe valide (longueur 8) → désormais refusé car < 12 caractères
    $this->assertSame(false, verifPassword("qamQdVD3"));

    // 12 caractères, avec minuscule, majuscule, chiffre ET caractère spécial
    // score = 1*(1+2+3+4) = 10 >= 10 → true
    $this->assertSame(true, verifPassword("qamQdVD3!abc"));

    // 14 caractères, toutes conditions remplies → true
    $this->assertSame(true, verifPassword("Qam3!dvDbAbc12"));
}
```

---

### Question A.3.3 – Champ `dateMajMDP` et fonction `renouvelleMDP`

#### a) Requête pour ajouter le champ `dateMajMDP`

En s'appuyant sur la documentation MySQL (Document commun 2) :

```sql
ALTER TABLE Utilisateur
ADD dateMajMDP DATE NOT NULL DEFAULT (CURRENT_DATE());
```

> `NOT NULL` car le champ est obligatoire. `DEFAULT (CURRENT_DATE())` assure l'initialisation automatique à la date du jour lors de la création d'un compte.

#### b) Fonction stockée `renouvelleMDP`

```sql
CREATE FUNCTION renouvelleMDP(idEleve INT)
RETURNS BOOLEAN
BEGIN
    DECLARE v_dateMaj DATE;
    DECLARE v_retour BOOLEAN DEFAULT FALSE;

    SELECT dateMajMDP INTO v_dateMaj
    FROM Utilisateur
    WHERE id = idEleve;

    IF DATE_ADD(v_dateMaj, INTERVAL 90 DAY) < CURRENT_DATE() THEN
        SET v_retour = TRUE;
    END IF;

    RETURN v_retour;
END
```

> La fonction retourne `TRUE` si la date de dernière modification du mot de passe + 90 jours est **antérieure** à aujourd'hui, c'est-à-dire si le mot de passe n'a pas été changé depuis plus de 90 jours.

---

## DOSSIER B – Prise en compte des conclusions de l'audit de sécurité

---

### Question B.1.1 – Conséquence principale d'une déclaration abusive d'échec ETG

La principale conséquence pour Easy2Drive est une **perte financière directe** : en accordant abusivement la « Garantie Réussite », l'entreprise rembourse à l'élève des frais de présentation à un nouvel examen alors que les conditions ne sont pas réellement remplies. À grande échelle, si de nombreuses auto-écoles exploitent cette faille, le coût pourrait être très significatif et menacer la viabilité économique de cette offre commerciale.

Il y a également un risque de **préjudice d'image** si la fraude est découverte publiquement, et un risque **juridique** si Easy2Drive est tenue pour responsable de ne pas avoir sécurisé ce processus.

---

### Question B.1.2 – Analyse et correction du déclencheur `check_garantie_reussite`

#### a) Conditions non implémentées ou mal implémentées

En comparant le Document B1 (conditions) avec le Document B2 (code du trigger) :

| Condition (Document B1) | État dans le trigger |
|---|---|
| La Garantie Réussite n'est accordée qu'une seule fois après le **premier** échec | ✅ Ligne 7 : vérifié (`OLD.echecEtg = TRUE AND NEW.echecEtg = TRUE`) |
| L'échec doit dater de **moins de 6 mois** | ❌ **Mal implémenté** : ligne 12, la condition est inversée. `DATE_ADD(NEW.dateEtg, INTERVAL 6 MONTH) >= NOW()` signifie que l'on déclenche l'erreur quand l'échec DATE **de moins de 6 mois**, alors qu'il faudrait déclencher l'erreur quand l'échec date **de plus de 6 mois**. |
| Au moins **25 séries** de quiz passées | ✅ Ligne 16-20 : correctement vérifié |
| Au moins **4 examens blancs** passés | ❌ **Non implémenté** : aucune vérification du nombre d'examens blancs passés |
| Moyenne d'au moins **34/40** sur les **4 meilleurs** examens blancs | ✅ Lignes 21-25 : correctement implémenté |

#### b) Code source corrigé

```sql
-- Correction ligne 12 : inversion de la condition (> au lieu de >=)
IF DATE_ADD(NEW.dateEtg, INTERVAL 6 MONTH) < NOW() THEN
    SIGNAL SQLSTATE '10002'
    SET MESSAGE_TEXT = 'Garantie réussite : échec trop ancien';
END IF;

-- Ajout : vérification du nombre d'examens blancs (au moins 4)
DECLARE v_nbExamen INT;

SELECT COUNT(*) INTO v_nbExamen
FROM Passer
WHERE idEleve = NEW.id;

IF v_nbExamen < 4 THEN
    SIGNAL SQLSTATE '10004'
    SET MESSAGE_TEXT = 'Garantie réussite : nombre d examens blancs insuffisant';
END IF;
```

**Trigger complet corrigé :**

```sql
CREATE TRIGGER check_garantie_reussite
BEFORE UPDATE ON Eleve
FOR EACH ROW
BEGIN
    DECLARE v_nbSerie INT;
    DECLARE v_nbExamen INT;
    DECLARE v_scoreMoyen DOUBLE;

    IF OLD.echecEtg = TRUE AND NEW.echecEtg = TRUE THEN
        SIGNAL SQLSTATE '10001'
        SET MESSAGE_TEXT = 'Garantie réussite : deuxième échec';
    END IF;

    -- Correction : < NOW() au lieu de >= NOW()
    IF DATE_ADD(NEW.dateEtg, INTERVAL 6 MONTH) < NOW() THEN
        SIGNAL SQLSTATE '10002'
        SET MESSAGE_TEXT = 'Garantie réussite : échec trop ancien';
    END IF;

    SELECT COUNT(*) INTO v_nbSerie FROM Evaluer WHERE idEleve = NEW.id;
    IF v_nbSerie < 25 THEN
        SIGNAL SQLSTATE '10003'
        SET MESSAGE_TEXT = 'Garantie réussite : nombre de séries insuffisant';
    END IF;

    -- Ajout : vérification du nombre d'examens blancs
    SELECT COUNT(*) INTO v_nbExamen FROM Passer WHERE idEleve = NEW.id;
    IF v_nbExamen < 4 THEN
        SIGNAL SQLSTATE '10004'
        SET MESSAGE_TEXT = 'Garantie réussite : nombre d examens blancs insuffisant';
    END IF;

    SELECT AVG(examenScore) INTO v_scoreMoyen FROM (
        SELECT examenScore FROM Passer
        WHERE idEleve = NEW.id
        ORDER BY examenScore DESC LIMIT 4
    ) AS MeilleureNotes;

    IF v_scoreMoyen < 34 THEN
        SIGNAL SQLSTATE '10005'
        SET MESSAGE_TEXT = 'Garantie réussite : score examens blancs insuffisant';
    END IF;

    -- Garantie Réussite attribuée
END
```

---

### Question B.2.1 – Complétion du schéma de la base `BD_RGPD_LOGS`

D'après l'entretien (Document B3) et la maquette (Document B4), chaque événement journalisé doit permettre de savoir :
- **Qui** a agi (utilisateur, nom, prénom, rôle)
- **Quelle action** a été effectuée (consultation, insertion, modification, suppression)
- **Sur quelle table** et **quel enregistrement** (n° ID de l'enregistrement concerné)
- **Quand** (date et heure)
- **Pour quelle auto-école** (contexte organisationnel)

**Schéma relationnel complété :**

```
Auto-Ecole (id, raisonSociale, codePostal, ville)
  Clé primaire : id

Utilisateur (id, nom, prenom, idAutoEcole, idRole)
  Clé primaire : id
  Clé étrangère : idAutoEcole → Auto-Ecole(id)
  Clé étrangère : idRole → Role(id)

Role (id, nom)
  Clé primaire : id
  Valeurs possibles : 'Directeur', 'Formateur', 'Eleve', 'Moderateur'

Evenement (id, dateHeure, action, nomTable, idEnregistrement, idUtilisateur)
  Clé primaire : id
  Clé étrangère : idUtilisateur → Utilisateur(id)
  action : 'Consultation' | 'Création' | 'Modification' | 'Suppression'
```

**Diagramme de classes complété (description textuelle) :**

```
Auto-Ecole (1) ────── (1..*) Utilisateur (1) ────── (1..*) Evenement
                              Utilisateur (1) ────── (1) Role
```

---

### Question B.2.2 – Créer l'utilisateur `APPLI_RGPD_LOGS`

L'application Easy2Drive se connecte depuis le serveur `Easy2Drive.fr` (Document B5) :

```sql
CREATE USER 'APPLI_RGPD_LOGS'@'Easy2Drive.fr'
IDENTIFIED BY 'motDePasseSecurise';
```

---

### Question B.2.3 – Attribuer les droits nécessaires

L'application doit uniquement **ajouter des données** (pas de lecture, modification ou suppression) → droit `INSERT` uniquement :

```sql
GRANT INSERT ON BD_RGPD_LOGS.* TO 'APPLI_RGPD_LOGS'@'Easy2Drive.fr';
```

---

### Question B.2.4 – Conservation et purge des journaux

#### a) Durée de conservation conforme CNIL

D'après le Document CNIL 3 : *« Ces journaux doivent conserver les événements sur une **période glissante ne pouvant excéder six mois** (sauf obligation légale ou risque particulièrement important) »*.

La durée de conservation recommandée est donc de **6 mois maximum**.

#### b) Document RGPD où consigner cette durée

Cette durée doit être consignée dans le **registre des activités de traitement** (obligatoire pour les responsables de traitement selon l'article 30 du RGPD). Ce registre recense notamment : la finalité du traitement, les catégories de données collectées, les durées de conservation et les mesures de sécurité mises en place.

#### c) Solution technique pour la purge automatique

Mettre en place un **événement planifié MySQL** (MySQL Event Scheduler) qui s'exécute automatiquement selon une fréquence définie (par exemple chaque nuit) et supprime tous les enregistrements de la base `BD_RGPD_LOGS` dont la date est antérieure à 6 mois :

```sql
-- Exemple de description de la solution (sans implémentation complète) :
-- Créer un EVENT MySQL qui tourne tous les jours à minuit
-- et exécute : DELETE FROM Evenement WHERE dateHeure < DATE_SUB(NOW(), INTERVAL 6 MONTH)
```

Cette solution est entièrement automatique, ne nécessite aucune intervention humaine et garantit le respect permanent de la durée de conservation.

---

## DOSSIER C – Mise en œuvre de contre-mesures dans la gestion des avis

---

### Question C1.1 – Méthode `getNbMaxAvisAtteint` de la classe `Eleve`

D'après le Document C1, `$lesAvis` est un tableau de 0 à 3 `Avis`. La méthode doit retourner `true` si l'élève a déjà déposé 3 avis :

```php
public function getNbMaxAvisAtteint(): bool
{
    return (count($this->lesAvis) >= 3);
}
```

---

### Question C1.2 – Complétion de la méthode `monAvis`

L'élève ne doit pas pouvoir accéder au formulaire si :
- Il a déjà atteint le nombre maximum d'avis (3), **OU**
- Il a déjà un avis en attente de modération (non encore modéré).

En s'appuyant sur Document C1 (`getDernierAvis()`, `getModere()`) et Document C3 :

```php
if (
    $user->getNbMaxAvisAtteint()
    || (count($user->getLesAvis()) > 0 && !$user->getDernierAvis()->getModere())
) {
    // l'utilisateur est redirigé vers l'accueil
    return $this->redirectToRoute('home');
}
```

**Explication :**
- `getNbMaxAvisAtteint()` → l'élève a déjà 3 avis : accès bloqué définitivement.
- `count($user->getLesAvis()) > 0 && !$user->getDernierAvis()->getModere()` → l'élève a un avis en cours de modération (non encore traité) : accès bloqué jusqu'à la décision du modérateur.

---

### Question C1.3 – Analyse de l'injection SQL

#### a) Résultat dans la base de données après l'injection

Le champ `txtContenu` contient une injection qui ferme prématurément la requête `INSERT` en cours et ajoute plusieurs enregistrements supplémentaires dans la table `Avis`. Depuis le compte de l'élève 12, l'injection insérerait les enregistrements suivants dans la table `Avis` :

1. `'Quelle incompétence!'` (date=now(), publie=true, modere=true, note=5)
2. `'A fuir absolument'` (date=now(), publie=true, modere=true, note=5)
3. `'Accueil froid, moniteurs désagréables'` (date=now(), publie=true, modere=true, note=5)
4. `'Aucun point positif'` (date=now(), publie=true, modere=true, note=5)
5. `'Choisissez une autre auto-école'` (date=now(), publie=true, modere=true, note=5)
6. `'formation OK` (avis de l'élève 12, partiellement injecté)

Ces avis sont insérés avec `publie=true` et `modere=true`, ce qui signifie qu'ils sont **immédiatement publiés et considérés comme modérés** sans passer par le processus de modération.

#### b) Comment cette injection contourne les mesures mises en place

Les mesures précédentes (vérification du nombre d'avis, accès au formulaire conditionné) agissent au niveau **applicatif PHP** et vérifient uniquement qu'un seul avis est soumis via le formulaire. L'injection SQL contourne totalement ces vérifications car :

- Elle agit directement au niveau de la **requête SQL** dans `insertUnAvis()`.
- En forgeant le contenu du champ texte, l'attaquant insère **plusieurs lignes d'un seul coup** dans la même requête.
- Les avis injectés ont `publie=true` et `modere=true`, **contournant la modération** a posteriori.
- La limite de 3 avis par élève est contournée car les enregistrements sont insérés directement en base sans passer par la logique applicative.

#### c) Solution pour corriger la vulnérabilité

Utiliser des **requêtes préparées avec paramètres liés** (prepared statements) au lieu de la concaténation de chaînes dans la méthode `insertUnAvis()`. Les requêtes préparées séparent le code SQL des données, rendant toute injection impossible car les valeurs saisies par l'utilisateur sont traitées comme des données pures et non comme du code SQL.

Exemple de correction dans `insertUnAvis()` :

```php
public function insertUnAvis(Avis $unAvis)
{
    $req = "INSERT INTO avis (contenu, dateDepot, publie, modere, idEleve)
            VALUES (:contenu, now(), :publie, :modere, :idEleve)";
    $res = PdoEasy2Drive::$monPdo->prepare($req);
    $res->bindParam(':contenu', $unAvis->getContenu(), PDO::PARAM_STR);
    $res->bindParam(':publie',  $unAvis->getPublie(),  PDO::PARAM_BOOL);
    $res->bindParam(':modere',  $unAvis->getModere(),  PDO::PARAM_BOOL);
    $res->bindParam(':idEleve', $unAvis->getLEleve()->getId(), PDO::PARAM_INT);
    $res->execute();
}
```

---

### Question C2.1 – Méthode `getDoublonMail` de `PdoEasy2Drive`

La méthode doit retourner `true` si l'adresse email passée en paramètre apparaît chez **plusieurs élèves** dans la table `Utilisateur` :

```php
public function getDoublonMail($unEmail): bool
{
    $req = "SELECT COUNT(*) AS nb
            FROM Utilisateur
            JOIN Eleve ON Utilisateur.id = Eleve.idUtilisateur
            WHERE Utilisateur.email = :email";
    $res = PdoEasy2Drive::$monPdo->prepare($req);
    $res->bindParam(':email', $unEmail, PDO::PARAM_STR);
    $res->execute();
    $result = $res->fetch();
    return ($result['nb'] > 1);
}
```

> La méthode utilise une **requête préparée** (bonne pratique anti-injection SQL) et retourne `true` si l'adresse est associée à plus d'un élève.

---

### Question C2.2 – Complétion de `listeAvis` dans `AvisModerateurController`

Il faut calculer `$doublonMail` pour chaque élève en appelant `getDoublonMail()` avec l'email de l'élève, puis l'ajouter au tableau `$tabDernierAvisParEleve` :

```php
foreach ($lesEleves as $unEleve) {
    if ($unEleve->getNeph() == null) {
        $pasDeNeph = true;
    } else {
        $pasDeNeph = false;
    }

    // Ajout : vérification du doublon d'adresse email
    $doublonMail = $PdoEasy2Drive->getDoublonMail($unEleve->getEmail());

    $tabDernierAvisParEleve[] = [
        'leEleve'    => $unEleve->getIdentite(),
        'avis'       => $unEleve->getDernierAvis(),
        'nbRefus'    => $unEleve->getNbAvisRefuse(),
        'pasDeNeph'  => $pasDeNeph,
        'doublonMail' => $doublonMail   // ajouté
    ];
}

return $this->render(
    'avis/tbbModerateur.html.twig',
    ['lesAvisAModerer' => $tabDernierAvisParEleve]
);
```

---

*Correction réalisée sur la base du sujet BTS SIO SLAM – U6 Cybersécurité – Session 2022 (Code sujet : 22SI5SLAM)*
