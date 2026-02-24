# BTS SIO SLAM – U6 Cybersécurité (Session 2023) – Cas « Lama Zoo »

## Corrigé (complet avec les documents fournis)

> Ce corrigé couvre toutes les questions A.1 à C.6. Les documents fournis dans la conversation permettent maintenant de répondre précisément à B.1–B.4 et C.1. Le document C4 (tableau d’honneur original) n’est pas fourni : la réponse C.6 propose donc une version pseudonymisée type, sans reprise des données réelles.

---

# DOSSIER A — Refonte du système d’habilitation des applications métier

## A.1
### a) Force brute et efficacité sur le mot de passe
Une attaque **par force brute** consiste à tester automatiquement un grand nombre de mots de passe (toutes les combinaisons ou un dictionnaire de mots de passe courants) jusqu’à trouver le bon.

Elle a été efficace pour compromettre le mot de passe de M. Breto car **« 1234Travail »** est un mot de passe **faible et prédictible** :
- la suite **1234** est très fréquente dans les dictionnaires d’attaque ;
- le mot **Travail** est courant et lié au contexte ;
- donc l’entropie est faible → le temps de cassage est réduit.

À cela s’ajoutent des pratiques aggravantes relevées sur site :
- mot de passe noté au dos du clavier (compromission physique possible) ;
- session restée ouverte sur un poste (accès direct sans authentification).

### b) Deux moyens de sensibilisation
Exemples :
- **formation / atelier** de sensibilisation (mots de passe, verrouillage session, phishing) ;
- **campagne interne** (affiches, mails, quizz, e-learning) ;
- **simulations de phishing** suivies d’un débrief ;
- rappel et contrôle de l’application de la **charte informatique**.

---

## A.2
### a) Risque de non-traçabilité
Sans authentification applicative, plusieurs personnes peuvent utiliser l’application après ouverture de session Windows. Les actions (création/modification/suppression) ne sont alors pas attribuables de façon certaine à une personne : on perd la **traçabilité** et la **responsabilité** (audit/investigation difficiles).

### b) Risque de perte de confidentialité
Sans authentification applicative, toute personne ayant accès à un poste du service (ou à une session ouverte) accède aux données de l’application. Il n’y a pas de contrôle d’accès par profil : risque de **consultation non autorisée** et de **fuite de données**.

---

## A.3
L’utilisation de rôles applicatifs distincts (comptes SGBD différents selon le rôle) renforce la sécurité car :
- application du **moindre privilège** (un rôle SQL ne possède que les droits nécessaires) ;
- réduction de l’impact en cas de faille (ex. injection SQL) : le compte DB ne peut pas faire plus que ce qui est autorisé ;
- cloisonnement (lecture seule vs écriture) ;
- meilleure gestion et audit des droits au niveau SGBD.

---

## A.4
### a) Pourquoi ces manques sont des vulnérabilités
- **Absence de durée de vie** : les comptes temporaires (stagiaires/saisonniers) peuvent rester actifs après départ → comptes oubliés exploitables.
- **Plusieurs rôles pour une même application** : cumul de privilèges, incohérences d’autorisation, difficulté de révocation → risque d’escalade.

### b) Modifications de la base
Objectifs :
1) un personnel ne doit avoir **qu’un seul rôle** par application ;
2) les habilitations doivent être **bornées dans le temps**.

Proposition :
- Ajouter `dateDebut` et `dateFin` dans `EstHabilite`.
- Modifier la clé primaire pour imposer l’unicité `(numMatriculePerso, idAppli)`.

Exemple (à adapter selon SGBD/contraintes existantes) :
```sql
ALTER TABLE EstHabilite
  ADD COLUMN dateDebut DATE NOT NULL,
  ADD COLUMN dateFin DATE NULL;

ALTER TABLE EstHabilite
  DROP PRIMARY KEY,
  ADD PRIMARY KEY (numMatriculePerso, idAppli);
```

---

## A.5 — Trigger `after_update_habilitation`
Objectif : en cas de modification d’une habilitation, insérer dans `HistoHabilitation` un message :
`Modification du rôle [id-ancien-role] à [id-nouveau-role]`.

```sql
DELIMITER $$

CREATE TRIGGER after_update_habilitation
AFTER UPDATE ON EstHabilite
FOR EACH ROW
BEGIN
  IF OLD.idRoleAppli <> NEW.idRoleAppli THEN
    INSERT INTO HistoHabilitation (dateheure, numMatriculePerso, idAppli, action)
    VALUES (
      NOW(),
      OLD.numMatriculePerso,
      OLD.idAppli,
      CONCAT('Modification du rôle ', OLD.idRoleAppli, ' à ', NEW.idRoleAppli)
    );
  END IF;
END$$

DELIMITER ;
```

Remarque : le trigger fourni en A3 contient des guillemets typographiques. En SQL MySQL il faut utiliser `'...'`.

---

## A.6
### a) Intérêt des transactions
Créer/supprimer un rôle applicatif implique deux opérations indissociables :
- création/suppression du **compte MySQL** ;
- insertion/suppression de la ligne dans **RoleApplicatif**.

Une transaction garantit l’atomicité : si une des opérations échoue, on fait un `ROLLBACK` et on évite un état incohérent (compte DB sans rôle applicatif ou l’inverse).

### b) Compléter `deleteRole()`
Objectif : supprimer l’enregistrement `RoleApplicatif` puis supprimer le compte MySQL.

```php
public function deleteRole(string $id, string $idAppli) : string
{
   $message = "";
   try {
      $this->monPdo->beginTransaction(); // début de la transaction

      // Suppression dans RoleApplicatif
      $req = $this->monPdo->prepare(
        'DELETE FROM RoleApplicatif WHERE idAppli = :idAppli AND idRoleAppli = :idRole ;'
      );
      $req->bindParam(':idAppli', $idAppli, PDO::PARAM_STR);
      $req->bindParam(':idRole', $id, PDO::PARAM_STR);
      $resultat = $req->execute();

      // Suppression du compte MySQL correspondant
      $req = $this->monPdo->prepare('DROP USER :idUser ;');
      $req->bindParam(':idUser', $id, PDO::PARAM_STR);
      $resultat = $resultat + $req->execute();

      $this->monPdo->commit(); // fin de la transaction

      if ($resultat) { $message = "ok"; }
   }
   catch (PDOException $e) {
      $this->monPdo->rollback(); // annulation
      $message = "Erreur !: " .$e->getMessage();
   }
   return $message;
}
```

---

# DOSSIER B — Sécurisation du recueil des avis (XSS)

## B.1
### a) Rôle de `before()` dans `AuthGuard`
D’après le document B5, `AuthGuard::before()` (lignes 3–9) vérifie si `session()->get('isLoggedIn')` est vrai. Sinon, il **redirige vers `/connexion`**.

Donc le rôle du `before` est de **bloquer l’accès** aux routes protégées si l’utilisateur n’est pas authentifié.

### b) Un attaquant doit-il être authentifié pour insérer un commentaire ?
Oui, car le fichier de routes (B3) protège :
- la route du formulaire (ligne 8) avec `['filter' => 'authGuard']` ;
- la route d’enregistrement (ligne 9) avec `['filter' => 'authGuard']`.

Donc sans authentification, l’accès est redirigé vers `/connexion`.

---

## B.2
### a) Pourquoi XSS stockée ?
Le commentaire contenant du JavaScript est **enregistré en base** (via `save($data)` dans B1) puis **réaffiché** sur la page des commentaires. Le script s’exécute à chaque affichage : c’est une XSS **stockée**.

### b) Pourquoi plus de victimes que XSS reflétée ?
Une XSS stockée touche **tous les visiteurs** qui consultent la page contenant la donnée stockée, tant qu’elle n’est pas supprimée/modérée. Une XSS reflétée ne s’exécute que pour les victimes qui ouvrent une URL/piège spécifique.

---

## B.3
### a) Pourquoi filtrer/échapper les données venant de la BDD avant affichage ?
Parce qu’une donnée en base peut contenir une charge XSS (attaque stockée). Échapper à l’affichage empêche l’exécution de scripts côté navigateur.

### b) Pourquoi filtrer/échapper les données du formulaire avant insertion en BDD ?
Pour éviter de **stocker** du contenu malveillant (réduction d’impact, limitation de propagation) et protéger d’autres usages ultérieurs (exports, back-office, réutilisations).

---

## B.4 (avec numéros de lignes)
### a) Modifier `commentStore` (B1) pour neutraliser le JS à l’enregistrement
La ligne vulnérable est la ligne 27 :

**Ligne 27 (remplacer)**
```php
'commentaireEvaluer' => esc($this->request->getVar('comment'), 'html'),
```

### b) Modifier la vue `coms.php` (B2) pour empêcher l’exécution à l’affichage
La ligne vulnérable est la ligne 4 :

**Ligne 4 (remplacer)**
```php
echo esc($com, 'html')."<br/>";
```

---

# DOSSIER C — Sécurisation des activités de parrainage

## C.1 — 5 indices de phishing (sur le mail fourni)
À partir du courriel C1 :
1) **Adresse expéditeur suspecte** : `zomagic.yahoo-micro@businessmail.com` n’est pas un domaine officiel `lamazoo.com`.
2) **Objet trop promotionnel / générique** : « Offre Spéciale ».
3) **Formulation inhabituelle / fautes** : « nous vous offront », « 4 entrées gratuite », accents/espaces incorrects.
4) **Lien douteux / non explicite** : « cestla fete enfamille » (pas une URL claire, pas de domaine visible, incite au clic).
5) **Signature approximative** : « Léquipe zoo » sans informations officielles (coordonnées, mentions, etc.).

---

## C.2 — Deux infractions possibles
Exemples :
- **Escroquerie** (ou tentative) : obtenir un avantage via tromperie.
- **Accès frauduleux à un STAD** (et éventuellement suppression de compte/données).

---

## C.3 — CSRF
### a) Client vs serveur
**Synchronizer Token Pattern (session)** :
- Serveur : token CSRF stocké en **session**
- Client : token transmis dans le formulaire (champ caché) ou URL

**Double Submit Cookie** :
- Client : token dans un **cookie** + token dans le corps (champ caché)
- Serveur : vérifie la correspondance des deux tokens (pas de stockage session obligatoire)

### b) Activer la protection CSRF session + formulaires
Dans `Security` (doc B4/C3) :
- passer `public $csrfProtection = 'session';`

Dans `Filters` :
- activer le filtre `csrf` dans `$globals['before']`.

Dans les vues :
- utiliser `<?= csrf_field() ?>` (si form_helper) ou
```html
<input type="hidden" name="<?= csrf_token() ?>" value="<?= csrf_hash() ?>" />
```

---

## C.4 — Exclure `/ws/...` du filtre CSRF
### a) Pourquoi l’API ne répond plus ?
Avec CSRF activé, les requêtes sont rejetées si elles n’envoient pas un token CSRF valide. Les routes API `/ws/...` (utilisées par des clients externes) n’envoient généralement pas ces tokens → rejet.

### b) Whitelist dans `Filters`
Dans la config Filters, ajouter une exception au filtre csrf pour les routes `ws/...` (d’après doc C3 : exceptions + regex possibles) :

Exemple :
```php
'csrf' => ['except' => ['ws/.*']]
```

(ou `ws*` selon la convention retenue par l’application)

---

## C.5 — Requêtes SQL (vue + droits)
D’après C5/C6, on doit exposer : Nom, Espèce, Année de naissance, Poids (et idéalement photo).

```sql
-- Retirer les droits actuels trop larges
REVOKE ALL ON BdAnimaux.animal FROM 'site_public';

-- (optionnel si nécessaire)
REVOKE ALL ON BdAnimaux.espece FROM 'site_public';

-- Créer la vue
CREATE VIEW BdAnimaux.vueAnimal AS
SELECT
  a.numAnimal,
  a.nomAnimal AS nom,
  e.nomCommunEspece AS espece,
  YEAR(a.dateNaissAnimal) AS annee_naissance,
  a.poidsAnimal AS poids_kg,
  a.photoAnimal AS photo
FROM Animal a
JOIN Espece e ON e.numEspece = a.numEspece;

-- Donner un droit lecture seule
GRANT SELECT ON BdAnimaux.vueAnimal TO 'site_public';
GRANT SHOW VIEW ON BdAnimaux.vueAnimal TO 'site_public';
```

---

## C.6 — Proposition de tableau d’honneur pseudonymisé
Le tableau original (C4) n’est pas fourni. Proposition : ne pas afficher de données directement identifiantes, mais un identifiant pseudonymisé stable.

Exemple :

| Rang | Identifiant parrain | Montant cumulé |
|-----:|----------------------|---------------:|
| 1    | Parrain #A3F9D2       | 1 250 €        |
| 2    | Parrain #7C10B8       | 1 100 €        |
| 3    | Parrain #19E441       |   980 €        |
| …    | …                    | …              |

Principe : afficher `Parrain #` + un identifiant calculé côté serveur (hash tronqué) à partir de l’identifiant interne + un sel secret.
