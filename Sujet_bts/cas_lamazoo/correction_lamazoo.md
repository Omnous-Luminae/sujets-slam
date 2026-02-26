# Correction – BTS SIO Option SLAM · Session 2023
## U6 – Cybersécurité des services informatiques
### Cas Lama Zoo

---

## DOSSIER A – Refonte du système d'habilitation des applications métier

---

### Question A.1

#### a) Attaque par force brute et efficacité sur le mot de passe de M. Breto

Une **attaque par force brute** consiste à tester automatiquement et de manière exhaustive toutes les combinaisons possibles de caractères (lettres, chiffres, symboles) jusqu'à trouver le mot de passe correct. Un logiciel automatisé envoie des milliers de tentatives de connexion en très peu de temps.

L'attaque a été efficace sur le compte de M. Breto car son mot de passe `1234Travail` présente plusieurs faiblesses :
- Il est **court** et **prévisible** (suite numérique `1234` suivie d'un mot du dictionnaire).
- Il ne contient **pas de caractères spéciaux**.
- Il était **noté en clair** au dos du clavier, ce qui constitue une vulnérabilité physique supplémentaire (attaque possible sans même recourir à la force brute).

Un dictionnaire ou une liste de mots de passe courants aurait rapidement trouvé ce mot de passe (attaque par dictionnaire, variante de la force brute).

#### b) Moyens de sensibilisation des employés

- **Sessions de formation / ateliers** : organiser des réunions ou formations dédiées à la sécurité informatique pour expliquer les risques liés aux mots de passe faibles et aux sessions ouvertes.
- **Diffusion d'une charte informatique illustrée** (affichages, e-mails, vidéos de sensibilisation) rappelant les bonnes pratiques (mot de passe fort, verrouillage de session).
- **Simulations d'attaques / exercices pratiques** : mettre en situation les employés (phishing simulé, test de robustesse des mots de passe) pour illustrer concrètement les risques.
- **Quiz ou e-learning** sur la sécurité, avec rappels réguliers.

---

### Question A.2

#### a) Risque de non-traçabilité

Sans authentification sur l'application, il est **impossible d'identifier quel utilisateur a effectué quelle action**. N'importe quel collaborateur connecté au poste peut utiliser l'application sans laisser de trace nominative. En cas d'incident (modification, suppression de données), il est impossible de déterminer le responsable, ce qui nuit à la **traçabilité des actions** et empêche toute investigation ou audit.

#### b) Risque de perte de confidentialité

Sans authentification, **tout utilisateur** ayant accès à un poste du service peut consulter l'ensemble des données de l'application, y compris des données sensibles auxquelles il ne devrait pas avoir accès selon son rôle. Il n'y a aucune gestion des droits : un stagiaire ou un visiteur occasionnel obtient le même niveau d'accès qu'un superviseur, ce qui viole le **principe de moindre privilège** et crée un risque de fuite d'informations confidentielles.

---

### Question A.3

L'utilisation de **rôles applicatifs différents** au niveau du pilote de connexion à la base de données améliore la sécurité de plusieurs façons :

- **Principe du moindre privilège** : chaque rôle ne dispose que des droits strictement nécessaires à ses fonctions (ex. : un rôle `atelier_reception` peut uniquement lire certaines tables, tandis qu'un rôle `atelier_superviseur` peut en modifier d'autres). Une compromission d'un compte à faibles droits ne met pas en danger l'ensemble des données.
- **Cloisonnement des accès** : un utilisateur malveillant ou une faille applicative exploitée avec un rôle limité ne peut pas effectuer d'opérations destructrices (DELETE, DROP) si ce rôle ne le permet pas.
- **Traçabilité** : les logs du SGBD enregistrent les actions par compte, permettant d'identifier quel rôle a effectué quelle opération.
- **Réduction de la surface d'attaque** : même si le code de l'application est vulnérable (injection SQL), les dommages sont limités aux droits accordés au rôle utilisé.

---

### Question A.4

#### a) Pourquoi ces manques constituent des vulnérabilités

**Absence de durée de vie des habilitations :**
Un employé qui quitte un service ou dont le contrat se termine conserve indéfiniment ses droits d'accès aux applications. Cela viole le principe de **gestion du cycle de vie des accès** et ouvre la porte à des accès non autorisés par d'anciens collaborateurs (stagiaires, saisonniers, employés mutés).

**Possibilité d'avoir plusieurs rôles sur la même application :**
Un personnel pourrait cumuler des droits contradictoires ou excessifs sur une même application, violant le principe de **séparation des privilèges**. Cela permet par exemple à un stagiaire de cumuler les droits d'un superviseur, ce qui contredit les spécifications fonctionnelles.

#### b) Modifications à apporter à la base de données

**Pour gérer la durée de vie des habilitations**, il faut ajouter des champs de date de début et de fin dans la table `EstHabilite` :

```sql
EstHabilite (numMatriculePerso, idAppli, idRoleAppli, dateDebutHabilitation, dateFinHabilitation)
  Clé primaire : numMatriculePerso, idAppli
  Clé étrangère : numMatriculePerso → Personnel
  Clé étrangère : idAppli, idRoleAppli → RoleApplicatif
```

> Remarque : `dateFinHabilitation` peut être NULL pour les habilitations permanentes.

**Pour garantir qu'un personnel ne peut avoir qu'un seul rôle par application**, il faut modifier la clé primaire de `EstHabilite` pour qu'elle ne comprenne que `(numMatriculePerso, idAppli)` au lieu de `(numMatriculePerso, idAppli, idRoleAppli)` :

```sql
EstHabilite (numMatriculePerso, idAppli, idRoleAppli, dateDebutHabilitation, dateFinHabilitation)
  Clé primaire : numMatriculePerso, idAppli        ← un seul rôle par personne par application
  Clé étrangère : numMatriculePerso → Personnel
  Clé étrangère : idAppli, idRoleAppli → RoleApplicatif
```

---

### Question A.5 – Déclencheur `after_update_habilitation`

En s'appuyant sur le modèle du déclencheur `after_delete_habilitation` (Document A3) et sur la documentation MySQL (Document A4) :

```sql
CREATE TRIGGER `after_update_habilitation`
AFTER UPDATE ON `EstHabilite`
FOR EACH ROW
BEGIN
    INSERT INTO HistoHabilitation
    VALUES (
        NOW(),
        old.numMatriculePerso,
        old.idAppli,
        CONCAT('Modification du rôle ', old.idRoleAppli, ' à ', new.idRoleAppli)
    );
END
```

> `old.idRoleAppli` contient l'ancien rôle avant la modification, `new.idRoleAppli` contient le nouveau rôle après la modification, conformément à la documentation MySQL.

---

### Question A.6

#### a) Intérêt des transactions

L'utilisation d'une **transaction** garantit que les deux opérations indissociables (création/suppression du compte utilisateur SGBD ET mise à jour de la table `RoleApplicatif`) sont exécutées de manière **atomique** : soit les deux réussissent ensemble, soit aucune n'est appliquée (rollback en cas d'erreur).

Sans transaction, il pourrait y avoir une incohérence : par exemple, le compte SGBD serait supprimé mais l'enregistrement dans `RoleApplicatif` persisterait, ou inversement. La transaction assure donc la **cohérence des données** entre le SGBD et la base `BdAuthentification`.

#### b) Code de la fonction `deleteRole()`

```php
public function deleteRole(string $id, string $idAppli) : string
{
    $message = "";
    try {
        $this->monPdo->beginTransaction(); // début de la transaction

        $req = $this->monPdo->prepare('DROP USER :idUser ;');
        $req->bindParam(':idUser', $id, PDO::PARAM_STR);
        $resultat = $req->execute();

        $req = $this->monPdo->prepare('DELETE FROM RoleApplicatif 
                                       WHERE idRoleAppli = :idRole 
                                       AND idAppli = :idAppli ;');
        $req->bindParam(':idRole', $id, PDO::PARAM_STR);
        $req->bindParam(':idAppli', $idAppli, PDO::PARAM_STR);
        $resultat = $resultat + $req->execute();

        $this->monPdo->commit(); // fin de la transaction par un commit

        if ($resultat) { $message = "ok"; }
    }
    catch (PDOException $e) {
        $this->monPdo->rollback(); // annulation de la transaction
        $message = "Erreur !: " . $e->getMessage();
    }
    return $message;
}
```

---

## DOSSIER B – Sécurisation du recueil des avis des participants aux ateliers

---

### Question B.1

#### a) Rôle de la méthode `before` de la classe `AuthGuard`

La méthode `before` s'exécute **avant** le traitement du contrôleur associé à la route. Elle vérifie si la variable de session `isLoggedIn` est définie et vraie. Si l'utilisateur n'est **pas authentifié**, il est automatiquement redirigé vers la page `/connexion`, empêchant ainsi l'accès à la ressource protégée.

En résumé : c'est un **filtre d'authentification** qui protège les routes sur lesquelles il est appliqué.

#### b) Authentification nécessaire pour insérer un commentaire ?

En examinant le fichier de configuration des routes (Document B3), la route d'affichage du formulaire (`commentform`) possède bien le filtre `authGuard` :

```
$routes->get('/ateliers/commentform/(:num)', ..., ['filter' => 'authGuard']);
$routes->post('/ateliers/commentstore', ..., ['filter' => 'authGuard']);
```

Cependant, **le filtre `authGuard` n'est appliqué qu'en tant que filtre de route**, et non dans `$globals`. Cela dit, les deux routes concernées (formulaire et envoi) sont bien protégées.

**Un attaquant non authentifié ne peut pas passer par l'interface Web normale** pour insérer un commentaire. Cependant, il pourrait techniquement envoyer une **requête HTTP POST directement** (via curl ou un outil similaire) vers `/ateliers/commentstore` si le filtre n'est pas correctement appliqué côté serveur. Avec le filtre `authGuard` en place sur la route POST, la requête devrait être bloquée et l'attaquant redirigé.

**Conclusion** : L'attaquant doit être préalablement authentifié pour insérer un commentaire via les routes protégées.

---

### Question B.2

#### a) Pourquoi s'agit-il d'une attaque XSS stockée ?

Le code JavaScript malveillant (`<script>alert("hello");</script>`) saisi dans le formulaire est **enregistré en base de données** lors de l'envoi du formulaire. Il est ensuite **restitué tel quel** dans la page des commentaires à chaque affichage. Le code malveillant est donc **persistant** : il est stocké de manière durable et exécuté à chaque consultation de la page par n'importe quel visiteur.

#### b) XSS stockée vs XSS reflétée : plus grande portée

Une **XSS reflétée** nécessite que chaque victime clique sur un lien spécialement forgé contenant la charge utile dans l'URL. L'attaquant doit donc diffuser ce lien à chaque cible potentielle.

Une **XSS stockée** ne nécessite qu'une seule injection : le code malveillant est stocké en base de données et s'exécute automatiquement pour **tous les visiteurs** qui consultent la page infectée, sans qu'aucune action particulière de leur part (autre que la visite) ne soit nécessaire. La portée est donc potentiellement bien plus large.

---

### Question B.3

#### a) Argument pour filtrer les données à l'affichage (issues de la BDD)

La base de données peut avoir été **compromise ou altérée directement** (injection SQL, accès non autorisé, données importées depuis une source externe). Des données malveillantes pourraient y avoir été introduites sans passer par les formulaires de l'application. Filtrer les données à l'affichage constitue une **défense en profondeur** qui protège les utilisateurs même si des données corrompues existent en base.

#### b) Argument pour filtrer les données avant écriture en BDD

Filtrer à l'écriture permet d'empêcher l'**injection de code malveillant dès la source**. Si les données sont filtrées avant stockage, elles sont neutres en base et ne peuvent plus nuire quelle que soit leur utilisation future (affichage, export, traitement par d'autres applications). Cela protège également contre les **injections SQL** qui pourraient être tentées via le formulaire.

---

### Question B.4

#### a) Modification de `commentStore` (Document B1) pour neutraliser le JavaScript à l'enregistrement

Ligne **27** : appliquer `esc()` sur la valeur du champ `comment` avant de la stocker.

```php
// Ligne 27 modifiée :
'commentaireEvaluer' => esc($this->request->getVar('comment'), 'html'),
```

#### b) Modification de la vue `coms.php` (Document B2) pour empêcher l'exécution du JavaScript à l'affichage

Ligne **4** : échapper la variable `$com` avant de l'afficher.

```php
// Ligne 4 modifiée :
echo esc($com, 'html') . "<br/>";
```

---

## DOSSIER C – Sécurisation des activités liées au parrainage d'animaux

---

### Question C.1 – Indices d'hameçonnage dans le courriel de M. Hardi

En analysant le Document C1, voici cinq types d'indices révélateurs :

1. **Adresse de l'expéditeur frauduleuse** : l'adresse `zomagic.yahoo-micro@businessmail.com` n'appartient pas au domaine officiel `lamazoo.com`. Un courriel légitime du parc aurait pour expéditeur une adresse en `@lamazoo.com`.

2. **Fautes d'orthographe et de grammaire** : "nous vous offront" (au lieu de "offrons"), "4 entrées gratuite" (au lieu de "gratuites"), "Léquipe zoo" (apostrophe manquante). Un courriel officiel ne contiendrait pas ces erreurs.

3. **Lien hypertexte trompeur** : le texte du lien ("cestla fete enfamille") ne correspond pas à son URL réelle (`https://lamazoo.com/profil/supprcmptconfirm`). L'URL pointe vers une action de suppression de compte, non vers une offre de billets.

4. **URL suspecte / action dangereuse** : l'hyperlien pointe vers `/profil/supprcmptconfirm`, une route qui confirme la **suppression du compte** de l'utilisateur. Aucune offre promotionnelle légitime ne redirigerait vers une telle action.

5. **Contenu incitatif / urgence artificielle** : le message exploite la flatterie ("cher Parrain", "votre fidèle soutien") et une promesse d'avantage gratuit (4 entrées) pour inciter à cliquer sans réfléchir. C'est une technique classique d'ingénierie sociale.

> Indice bonus : la mise en page sommaire et le manque de logo ou d'identité visuelle officielle du parc constituent également des signaux d'alerte.

---

### Question C.2 – Infractions pouvant être retenues

1. **Accès frauduleux à un système informatique** (article 323-1 du Code pénal) : en incitant M. Hardi à cliquer sur le lien pour supprimer son compte, l'auteur cherche à prendre le contrôle ou à nuire à un système informatique de manière frauduleuse.

2. **Escroquerie / usurpation d'identité** (articles 313-1 et 226-4-1 du Code pénal) : l'auteur se fait passer pour le parc Lama Zoo en utilisant son nom et son image pour tromper les parrains et les inciter à effectuer une action à leur détriment.

> On pourrait également mentionner : **atteinte aux systèmes de traitement automatisé de données** (STAD), ou **tentative d'extorsion** selon les circonstances.

---

### Question C.3

#### a) Éléments stockés côté client et côté serveur pour chaque solution CSRF

| Solution | Côté client (navigateur) | Côté serveur |
|---|---|---|
| **Synchronizer Token Pattern** (basé session) | Le jeton CSRF est envoyé dans un **champ caché du formulaire** (dans le corps de la requête HTTP) | Le jeton CSRF est stocké en **variable de session** côté serveur |
| **Double Submit Cookie Pattern** (basé cookie) | Le jeton CSRF est envoyé sous **deux formes** : un cookie HTTP ET un champ caché du formulaire | **Rien** n'est stocké côté serveur (vérification que les deux jetons reçus sont identiques) |

#### b) Modifications pour activer la protection CSRF basée sur la session (Synchronizer Token)

**Dans la classe `Security` (Document B4)**, modifier la valeur de `$csrfProtection` :

```php
// Ligne 3 modifiée :
public $csrfProtection = 'session';  // était 'cookie'
```

**Dans la classe `Filters` (Document B4)**, ajouter le filtre `'csrf'` dans le tableau `before` des `$globals` :

```php
public $globals = [
    'before' => [ 'honeypot', 'invalidchars', 'csrf' ],  // ajout de 'csrf'
    'after'  => [ 'toolbar' ],
];
```

**Ce que les développeurs devront ajouter dans leurs formulaires** : inclure le champ caché CSRF dans chaque formulaire protégé, en utilisant la fonction helper fournie par CodeIgniter :

```php
<?= csrf_field() ?>
```

Cette ligne génère automatiquement :
```html
<input type="hidden" name="{csrf_token}" value="{csrf_hash}" />
```

---

### Question C.4

#### a) Pourquoi les routes de l'API ne répondent plus ?

Depuis l'activation du filtre CSRF dans `$globals['before']`, **toutes les requêtes** passent par la vérification CSRF avant d'être traitées. Les routes de l'API (`/ws/animaux`, `/ws/hebergements`, `/ws/ateliers`) reçoivent des requêtes qui ne contiennent **pas de jeton CSRF** (car l'API est appelée sans formulaire HTML ni session). Le filtre rejette donc automatiquement ces requêtes, ce qui explique que l'API ne renvoie plus les réponses attendues.

#### b) Modifications pour mettre en place la liste blanche (whitelist)

En s'appuyant sur les routes API du Document B3 (lignes 22, 23, 24), qui commencent toutes par `/ws/`, et en suivant la syntaxe de CodeIgniter (Document C3) :

**Dans la classe `Filters`**, modifier l'ajout du filtre `csrf` pour inclure les exceptions :

```php
public $globals = [
    'before' => [
        'honeypot',
        'invalidchars',
        'csrf' => ['except' => ['ws*']]  // exclure toutes les routes commençant par 'ws'
    ],
    'after' => [ 'toolbar' ],
];
```

> L'expression `'ws*'` correspond à toutes les routes commençant par `ws` (comme `ws/animaux`, `ws/hebergements`, `ws/ateliers`). On peut aussi utiliser `'ws/.*'` selon la syntaxe regex de CodeIgniter.

---

### Question C.5 – Requêtes SQL pour sécuriser l'accès aux données animaux

En s'appuyant sur la fiche de l'animal (Document C6), la vue doit afficher : nom, espèce (nom commun), année de naissance, poids et commentaire. Il faut également pouvoir afficher la photo (photoAnimal).

```sql
-- 1. Révoquer tous les droits actuels du compte site_public sur la table animal
REVOKE ALL ON BdAnimaux.animal FROM 'site_public';

-- 2. Créer la vue vueAnimal avec les colonnes utiles au site Web
CREATE VIEW BdAnimaux.vueAnimal AS
    SELECT 
        a.nomAnimal,
        e.nomCommunEspece,
        YEAR(a.dateNaissAnimal) AS anneeNaissance,
        a.poidsAnimal,
        a.commentaire,
        a.photoAnimal
    FROM Animal a
    JOIN Espece e ON a.numEspece = e.numEspece;

-- 3. Accorder uniquement le droit SELECT sur la vue au compte site_public
GRANT SELECT ON BdAnimaux.vueAnimal TO 'site_public';
```

> Ainsi, le compte `site_public` ne peut plus accéder directement à la table `Animal` (suppression de ALL), n'a pas accès aux colonnes sensibles (localisation, statut de prêt `pretAnimal`, parents, numéro de zone, etc.), et ne peut qu'effectuer des lectures sur la vue restreinte.

---

### Question C.6 – Tableau d'honneur pseudonymisé

Le tableau actuel (Document C4) affiche des données personnelles sensibles : prénom, nom, adresse, code postal, ville, téléphone. Pour respecter la vie privée des parrains (RGPD) tout en permettant à chacun de se reconnaître, on peut proposer la pseudonymisation suivante :

| # | Parrain | Ville | Total |
|---|---------|-------|-------|
| 1 | Sylvie S. | Montpellier | 1 050,00 € |
| 2 | Linda M. | Millau | 20,00 € |

**Principes appliqués :**
- **Prénom conservé** (permet à la personne de se reconnaître) + **initiale du nom** (pseudonymisation partielle).
- **Ville conservée** (information générale, non précise).
- **Suppression** : nom complet, adresse postale, code postal, numéro de téléphone.
- Le **total des dons** est conservé car c'est la donnée principale du classement.

> Une alternative encore plus stricte serait d'utiliser un pseudo choisi par le parrain lors de son inscription, ce qui garantit une pseudonymisation totale selon le RGPD.

---

*Correction réalisée sur la base du sujet BTS SIO SLAM – U6 Cybersécurité – Session 2023 (Code sujet : 23SI6SLAM-1)*
