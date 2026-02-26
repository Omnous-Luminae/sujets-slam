# Correction – BTS SIO Option SLAM · Session 2024
## U6 – Cybersécurité des services informatiques
### Cas GSIC (Sdis de la ville de M.)

---

## DOSSIER A – Préparation de la mise en place d'une authentification unique (SSO)

---

### Question A1.1 – Objectif réglementaire de la traçabilité des accès

La traçabilité des accès a pour objectif réglementaire de **permettre la détection, l'investigation et la preuve** d'incidents de sécurité. Elle répond notamment aux exigences du **RGPD** (Règlement Général sur la Protection des Données) qui impose aux responsables de traitement de mettre en place des mesures techniques garantissant la sécurité des données personnelles, ainsi qu'aux recommandations de la **CNIL** et aux référentiels de sécurité (RGS, ISO 27001).

Concrètement, les journaux d'authentification permettent de :
- Vérifier qui a accédé à quelles ressources, et à quel moment.
- Détecter des tentatives d'intrusion ou des usurpations d'identité.
- Constituer des preuves en cas de litige ou d'investigation judiciaire.
- Vérifier le respect de la politique de sécurité et des habilitations.

---

### Question A1.2

#### a) Différence entre archivage et sauvegarde

| | Sauvegarde | Archivage |
|---|---|---|
| **Objectif** | Restaurer rapidement des données en cas de perte ou d'incident | Conserver des données sur le long terme à des fins légales, réglementaires ou probatoires |
| **Durée** | Court à moyen terme | Long terme |
| **Accès** | Fréquent (restauration opérationnelle) | Rare (consultation ponctuelle, contrôle) |
| **Modification** | Les données peuvent être écrasées/remplacées | Les données doivent être immuables |

#### b) Pourquoi les fichiers de journalisation des authentifications sont archivés

Les fichiers de journalisation des authentifications sont archivés car ils constituent des **preuves légales** en cas d'incident de sécurité, d'audit ou d'enquête. La réglementation (RGPD, CNIL) impose de pouvoir justifier des accès aux données personnelles sur une durée déterminée. L'archivage garantit la disponibilité de ces preuves sur le long terme, indépendamment des cycles de sauvegarde opérationnels.

---

### Question A1.3 – Confidentialité et intégrité lors de l'archivage

**Confidentialité :**
Les fichiers de journalisation sont compressés **avec chiffrement** avant leur transfert sur bandes magnétiques. La confidentialité est donc **garantie** : même si une bande était dérobée ou interceptée lors du transfert sur le réseau interne, les données seraient illisibles sans la clé de déchiffrement.

**Intégrité :**
L'intégrité **n'est pas garantie**. La procédure précise explicitement que la compression se fait **sans vérification des sommes de contrôle (empreinte numérique)**. Sans calcul et vérification de hash (MD5, SHA-256…) avant et après le transfert, il est impossible de détecter une altération accidentelle (erreur de transmission) ou intentionnelle (modification malveillante) des fichiers archivés.

**Recommandation :** Il faudrait calculer une empreinte numérique (hash) des fichiers avant leur transfert et la stocker séparément, afin de pouvoir vérifier ultérieurement que les archives n'ont pas été altérées.

---

### Question A2.1 – Vue `v_liste_comptes`

En s'appuyant sur le Document A1 (structure des 4 bases) et la documentation MySQL (Document A2) avec l'opérateur `UNION` :

```sql
CREATE VIEW BdInventaire.v_liste_comptes (origine, nom, prenom, compte_login, roles) AS

    SELECT 'Personnel', nomUser, prenomUser, login, rolesUser
    FROM Personnel.Compte_Employe

    UNION

    SELECT 'Formation', nom, prenom, compte, NULL
    FROM Formation.Utilisateur

    UNION

    SELECT 'Logistique', nom_compte, prenom_compte, compte, roles_compte
    FROM Logistique.Compte

    UNION

    SELECT 'Prevention', nom, prenom, login, role
    FROM Prevention.User;
```

> Remarque : la base `Formation` ne contient pas de champ rôle ; on retourne donc `NULL` pour cette colonne.

---

### Question A2.2 – Complétion de la modélisation de la base BdInventaire

D'après le diagramme de classes et le schéma entité-association (Document A3) :
- `APPLICATION` a un `id`, un `nomApplication` et un `nomBDD`.
- `COMPTE` a un `id`.
- La relation `Utiliser` est de cardinalité 0,n — 1,1 : un compte utilise une application, une application est utilisée par 0 à n comptes.

Il manque dans la modélisation la table de liaison entre `COMPTE` et les rôles, ainsi que les attributs nécessaires au programme `InventaireHabil`. La modélisation complétée est :

**Schéma relationnel de BdInventaire :**

```
Application(id, nomApplication, nomBDD)
  Clé primaire : id

Compte(id, login, nom, prenom, idApplication)
  Clé primaire : id
  Clé étrangère : idApplication → Application(id)

Role(id, nomRole, idApplication)
  Clé primaire : id
  Clé étrangère : idApplication → Application(id)

PossederRole(idCompte, idRole)
  Clé primaire : idCompte, idRole
  Clé étrangère : idCompte → Compte(id)
  Clé étrangère : idRole → Role(id)
```

> Cela permet d'associer plusieurs rôles à un compte (relation n,n entre Compte et Role) et de lier chaque rôle à une seule application conformément aux spécifications.

---

### Question A2.3

#### a) Créer le compte `prep_sso`

```sql
CREATE USER 'prep_sso'@'localhost' IDENTIFIED BY 'motDePasseSecurisé';
```

#### b) Attribuer les droits strictement nécessaires

Le programme `InventaireHabil` doit :
- **Lire** la vue `v_liste_comptes` (SELECT).
- **Insérer** des données dans les tables de `BdInventaire` (INSERT).

Il n'a pas besoin de modifier, supprimer, créer ou administrer quoi que ce soit.

```sql
-- Droit de lecture sur la vue
GRANT SELECT ON BdInventaire.v_liste_comptes TO 'prep_sso'@'localhost';

-- Droits d'insertion dans les tables de BdInventaire
GRANT INSERT ON BdInventaire.Application TO 'prep_sso'@'localhost';
GRANT INSERT ON BdInventaire.Compte TO 'prep_sso'@'localhost';
GRANT INSERT ON BdInventaire.Role TO 'prep_sso'@'localhost';
GRANT INSERT ON BdInventaire.PossederRole TO 'prep_sso'@'localhost';
```

> Principe du **moindre privilège** : on n'accorde que les droits strictement nécessaires aux opérations que le programme effectue réellement.

---

## DOSSIER B – Mise en place du service SSO pour le système de gestion administratif

---

### Question B1.1

#### a) Infractions commises par l'agent

En s'appuyant sur la charte informatique (Document B1, section 2.1.2) :

L'agent a **violé la règle 1 de la section 2.1.2** : *« Garder strictement confidentiel(s) son (ses) code(s) d'accès et ne jamais les communiquer à un tiers »*. En divulguant ses identifiants à son stagiaire, il a commis une **faute disciplinaire** au regard de la charte informatique qu'il a signée.

Sur le plan pénal, cette action peut également constituer une **mise en danger du système d'information** si cela facilite un accès non autorisé aux données personnelles du Sdis (violation du RGPD, article 32).

#### b) Le stagiaire est-il en faute ?

Oui. La charte informatique s'applique explicitement aux stagiaires (section 1.1 : *« les stagiaires exerçant leurs missions au sein de l'organisation »*). En utilisant les identifiants d'un autre utilisateur, le stagiaire a violé la **règle 2 de la section 2.1.2** : *« Ne pas utiliser les codes d'accès d'un autre utilisateur »*. Il est donc fautif, même si les identifiants lui ont été fournis volontairement.

#### c) Risques encourus par les deux personnes

- **L'agent** : sanctions disciplinaires (avertissement, suspension d'accès, voire licenciement selon la gravité), et potentiellement des poursuites civiles ou pénales si la divulgation a entraîné une violation de données personnelles.
- **Le stagiaire** : sanctions disciplinaires (rupture du stage), et potentiellement des poursuites pénales pour accès frauduleux à un système de traitement automatisé de données (article 323-1 du Code pénal), même si l'accès a été facilité par l'agent.

---

### Question B1.2 – Condition réglementaire pour que la charte s'impose aux employés

Pour avoir une portée juridique contraignante, la charte informatique doit avoir été :
1. **Portée à la connaissance des employés** (remise lors de l'embauche ou affichage accessible).
2. **Intégrée au règlement intérieur** de l'établissement ou annexée à celui-ci (dans les organisations de plus de 50 salariés, le règlement intérieur doit être soumis à consultation des représentants du personnel et déposé auprès de l'inspection du travail).
3. **Signée par chaque utilisateur**, attestant qu'ils en ont pris connaissance et en acceptent les termes.

Sans ces conditions, la charte ne peut pas fonder des sanctions disciplinaires.

---

### Question B1.3 – Données sensibles de la base de données Medical

Selon le RGPD (article 9), les **données sensibles** sont des catégories particulières de données, notamment les données relatives à la **santé**, à l'**origine ethnique** et à certaines caractéristiques biologiques.

En analysant le Document B3 :

**Données sensibles dans la table `Patient` :**
- `num_secu` (numéro de sécurité sociale) → donnée personnelle à caractère hautement sensible, liée à l'identité et à la santé.
- `genre_biologique` → donnée sensible (caractéristique physiologique).
- `pays_naissance` → peut révéler une origine ethnique/nationale (donnée sensible).

**Données sensibles dans la table `PatientAnonyme` :**
- `rhesus` → le sujet précise que le rhésus **n'est pas considéré comme une donnée sensible** dans ce contexte (car inscrit sur l'uniforme). Il n'est donc **pas** à retenir.

**Données sensibles dans la table `Visite` :**
- `taille`, `poids`, `masse_graisseuse`, `masse_musculaire`, `tension` → données de **santé** (données médicales relatives à l'état physique).
- `profil` → évaluation médicale individuelle (profil SIGYC0P) → donnée de **santé**.

**Données sensibles dans la table `Vaccination` :**
- L'association `id_anonyme` + `id_vaccin` constitue une donnée de **santé** (informations sur les vaccinations effectuées).

---

### Question B1.4 – Scénario de risque justifiant le chiffrement

**Scénario :** Un administrateur de base de données (DBA) ou un prestataire de maintenance externe, disposant d'un accès légitime au serveur SQL Server pour des raisons techniques, exploite cet accès pour **consulter directement les tables de la base Medical** sans passer par l'application.

Bien que les accès applicatifs soient sécurisés, un DBA peut interroger les tables directement via SQL Server Management Studio. Sans chiffrement des colonnes, il peut lire en clair le numéro de sécurité sociale, les données médicales (profil, tension, masse corporelle) et les données d'identification des sapeurs-pompiers.

Ces données pourraient être revendues, divulguées à des tiers (compagnies d'assurance, employeurs concurrents) ou utilisées pour nuire aux personnes concernées.

**Ce scénario justifie le chiffrement des colonnes sensibles** : même avec un accès direct à la base, un utilisateur non habilité ne verrait que des données chiffrées illisibles.

---

### Question B1.5 – Requêtes pour tester le point 4 du scénario (table `PatientAnonyme`, champ `rhesus`)

En s'appuyant sur le Document B4 (étapes 4a à 4d) et le Document B2 (syntaxe T-SQL) :

```sql
-- Étape 4a : Ajouter une nouvelle colonne chiffrée
ALTER TABLE PatientAnonyme ADD rhesus_chiffre varbinary(30);

-- Étape 4b : Renseigner la colonne chiffrée avec la donnée chiffrée
-- (nécessite d'ouvrir la clé symétrique d'abord)
OPEN SYMMETRIC KEY Medical_Key DECRYPTION BY CERTIFICATE Medical18;

UPDATE PatientAnonyme
SET rhesus_chiffre = EncryptByKey(Key_GUID('Medical_Key'), rhesus);

CLOSE SYMMETRIC KEY Medical_Key;

-- Étape 4c : Supprimer la colonne en clair
ALTER TABLE PatientAnonyme DROP COLUMN rhesus;

-- Étape 4d : Renommer la nouvelle colonne avec le nom d'origine
EXEC sp_rename 'PatientAnonyme.rhesus_chiffre', 'rhesus', 'COLUMN';
```

---

### Question B2.1 – Conséquences sécuritaires de l'absence d'authentification sur les routes de l'API

Élodie signale qu'**aucune route de l'API n'est soumise à authentification** : seul le code applicatif qui appelle l'API vérifie l'identité de l'utilisateur.

Cela implique les risques suivants :
- **Contournement de l'authentification** : n'importe quelle application ou personne connaissant l'URL de l'API peut appeler directement les routes (ex. via Postman, curl) sans être authentifiée, contournant totalement le contrôle d'accès de l'application cliente.
- **Accès non autorisé aux données** : un attaquant peut lire (`GET /formations`), créer, modifier ou supprimer des formations sans aucun contrôle d'identité côté serveur.
- **Attaque de type IDOR** (Insecure Direct Object Reference) : en appelant `DELETE /formations/{code}`, n'importe qui peut supprimer n'importe quelle formation.
- **Non-respect du principe de défense en profondeur** : la sécurité ne repose que sur une seule couche (le client), ce qui est insuffisant.

---

### Question B2.2 – Résolution du problème de mise à jour de formation (erreur 405)

**Problème identifié :**

L'erreur retournée est `405 Method Not Allowed` sur la route `/formations/F204591` avec la méthode **POST**. Or, d'après le Document B5, la mise à jour d'une formation est gérée par la méthode **`@PutMapping`** (`PUT`), pas `@PostMapping` (`POST`).

Élodie utilise `POST` dans Postman alors qu'elle devrait utiliser **`PUT`**.

**Explication à fournir à Élodie :**

Dans l'API REST développée avec Spring, les opérations CRUD sont mappées sur des méthodes HTTP distinctes :
- `POST /formations` → **créer** une nouvelle formation.
- `PUT /formations/{code}` → **mettre à jour** une formation existante.

Élodie envoie une requête `POST` vers `/formations/F204591`, ce qui ne correspond à aucune route définie (il n'existe pas de `@PostMapping("/formations/{code}")`). Le serveur retourne donc `405 Method Not Allowed`.

**Solution :** dans Postman, changer la méthode de `POST` à **`PUT`** en conservant la même URL `/formations/F204591` et le même corps JSON.

---

### Question B2.3 – Hypothèse sur l'erreur « Token verification failed »

**Hypothèse la plus probable : le jeton JWT a expiré.**

D'après le Document B6, l'`access_token` a une durée de validité de **300 secondes** (5 minutes). Élodie a obtenu son jeton puis a effectué une pause de **15 minutes** avant de l'utiliser. Le jeton est donc expiré depuis 10 minutes au moment de la requête.

Le serveur SSO rejette le jeton car sa date d'expiration (champ `exp` encodé dans le JWT) est dépassée, ce qui génère l'erreur `invalid_token / Token verification failed`.

**Solution :** utiliser le `refresh_token` (valide 1 800 secondes / 30 minutes) pour obtenir un nouvel `access_token` sans avoir à se réauthentifier, via la méthode `getToken()` sans paramètre à compléter.

---

### Question B2.4 – Complétion de la méthode `getToken()` sans paramètre

En s'appuyant sur le Document B8 (méthode `getToken(User leUser)` comme modèle) et les spécifications dans la Javadoc :

```java
public String getToken() {
    List<NameValuePair> params = new ArrayList<NameValuePair>();
    params.add(new BasicNameValuePair("refresh_token", this.refreshToken));
    params.add(new BasicNameValuePair("client_id", "gsic_api_rolebased"));
    params.add(new BasicNameValuePair("grant_type", "refresh_token"));
    this.requestToken(params);
    return this.token;
}
```

> Le paramètre `grant_type` vaut `"refresh_token"` (et non `"password"` comme pour l'authentification initiale). Le `refresh_token` actuel est passé pour obtenir un nouvel `access_token`.

---

### Question B3.1 – Impact du SSO sur le scénario de risque

#### a) Comment le SSO modifie ce scénario

Avant le SSO, si un pirate vole le mot de passe d'un sapeur-pompier pour l'application d'inscription aux formations, il n'accède qu'à **cette seule application**. Les conséquences sont limitées.

Après la mise en place du SSO, **un seul couple identifiant/mot de passe donne accès à toutes les applications** du système de gestion administratif. Le vol de ce mot de passe unique permettrait au pirate d'accéder à l'ensemble des applications (RH, formations, logistique, prévention, médical…), y compris des données personnelles et médicales sensibles.

**Conséquence : la gravité du scénario augmente considérablement.** Le risque, initialement noté gravité 2 / vraisemblance 2, devrait être réévalué à une gravité bien plus élevée (3 ou 4), puisque l'impact potentiel n'est plus limité à une seule application mais s'étend à tout le SI.

#### b) Piste d'amélioration pour minimiser le risque

La piste d'amélioration la plus adaptée est la mise en place de l'**authentification multi-facteurs (MFA)** sur le service SSO. Même si un attaquant vole le mot de passe, il ne pourra pas se connecter sans le second facteur (application OTP, SMS, clé physique FIDO2…).

Cela réduit fortement la **vraisemblance** du scénario (un mot de passe seul ne suffit plus), compensant ainsi l'augmentation de la gravité due au SSO.

---

## DOSSIER C – Adaptation de la politique de sécurité de l'application mobile Rescousse

---

### Question C1.1 – Type d'attaque contre lequel un mot de passe à 8 caractères est plus protecteur

Un mot de passe à 8 caractères (avec majuscules, minuscules, chiffres et caractères spéciaux, soit un espace de ~72 caractères) est beaucoup plus protecteur qu'un code PIN à 4 chiffres contre une **attaque par force brute**.

- Un code PIN à 4 chiffres offre `10^4 = 10 000` combinaisons possibles.
- Un mot de passe à 8 caractères (alphabet étendu ~72 caractères) offre `72^8 ≈ 7,2 × 10^14` combinaisons, soit environ **70 milliards de fois plus** de combinaisons à tester.

Le temps nécessaire pour parcourir exhaustivement toutes les combinaisons est donc incomparablement plus long, rendant la force brute pratiquement impossible dans un délai raisonnable.

---

### Question C1.2 – Distinction juridique entre reconnaissance faciale et mot de passe

Un mot de passe est une **donnée de connaissance** : il peut être changé, réinitialisé, partagé ou oublié. Il ne bénéficie pas d'une protection juridique spécifique en tant que donnée personnelle (c'est un secret, pas une caractéristique de la personne).

La **reconnaissance faciale** repose sur des **données biométriques** (gabarit du visage), qui sont des données **sensibles au sens du RGPD** (article 9) : elles permettent d'identifier une personne de manière unique et permanente, et ne peuvent pas être modifiées en cas de compromission.

Juridiquement :
- Le traitement de données biométriques est **interdit par défaut** et ne peut être mis en œuvre que dans des cas exceptionnels prévus par le RGPD (consentement explicite, nécessité pour la sécurité des personnes, etc.).
- En contexte professionnel (lieu de travail), la CNIL encadre strictement l'usage de la biométrie et exige notamment une **analyse d'impact (AIPD)** préalable.
- Les données biométriques ne peuvent pas être « changées » en cas de fuite, contrairement à un mot de passe.

---

### Question C1.3 – Code de la méthode `ajouterEntreeLog`

En s'appuyant sur le Document C2 (structure de `EntreeLog` et `DbLogRescousse`), le Document C3 (syntaxe SQLite INSERT) et le modèle de `supprimerEntreesLog` :

```java
public void ajouterEntreeLog(EntreeLog uneEntreeLog) {
    try {
        // Ouvre la base de données en écriture
        SQLiteDatabase db = this.getWritableDatabase();

        String sql = "INSERT INTO " + TABLE_NAME
            + " (date, heure, type, resultat, message) VALUES (?, ?, ?, ?, ?);";

        db.execSQL(sql, new Object[]{
            uneEntreeLog.getDate().toString(),
            uneEntreeLog.getHeure().toString(),
            uneEntreeLog.getType(),
            uneEntreeLog.getResultat(),
            uneEntreeLog.getMessage()
        });
    } catch (Exception ex) {
        traiterErreur("ajout entrée log", ex);
    }
}
```

> `id` n'est pas passé car c'est une clé primaire en `AUTOINCREMENT`. Les types `LocalDate` et `LocalTime` sont convertis en `String` (`.toString()`) car SQLite utilise le type `TEXT` pour les dates/heures.

---

### Question C1.4 – Complétion de la méthode `onCreate` de `LoginBiometrieActivity`

En s'appuyant sur le Document C5 et le tableau des valeurs à renseigner :

| Authentification | Résultat | Message |
|---|---|---|
| Succès | `"Succes"` | `"OK"` |
| Erreur | `"Echec"` | code erreur – texte erreur |

```java
// Dans onAuthenticationError :
@Override
public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
    super.onAuthenticationError(errorCode, errString);

    // Création et enregistrement de l'entrée log en cas d'erreur
    EntreeLog entreeLog = new EntreeLog(
        "LoginBiometrie",
        "Echec",
        errorCode + " - " + errString.toString()
    );
    dbLog.ajouterEntreeLog(entreeLog);

    // Affichage du message d'erreur à l'utilisateur
    snack(errString.toString());
}

// Dans onAuthenticationSucceeded :
@Override
public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
    super.onAuthenticationSucceeded(result);

    // Création et enregistrement de l'entrée log en cas de succès
    EntreeLog entreeLog = new EntreeLog(
        "LoginBiometrie",
        "Succes",
        "OK"
    );
    dbLog.ajouterEntreeLog(entreeLog);

    // Démarrer l'activité suivante
    startActivity(rescousseActivite);
}
```

---

### Question C1.5 – Analyse de la table `LogRescousse` au regard des recommandations CNIL

#### a) La table contient-elle toutes les données indispensables ?

D'après le Document C4, la CNIL recommande que chaque entrée de journal contienne :
- **L'auteur individuellement identifié** ✗ → la table `LogRescousse` ne contient pas d'identifiant de l'utilisateur (pompier) qui a tenté de se connecter. On sait seulement de quelle tablette provient la tentative (via `adMAC`), mais pas qui l'a effectuée.
- **L'horodatage** ✓ → `date` et `heure` sont présents.
- **L'équipement utilisé** ✓ → `adMAC` (adresse MAC de la tablette) identifie l'équipement.
- **La nature de l'opération** ✓ → `type` (LoginBiometrie ou LoginMdp) et `resultat` permettent de qualifier l'opération.

**Conclusion :** La table est **incomplète** : il manque un identifiant permettant d'identifier individuellement l'utilisateur (ex. : numéro de matricule du pompier), conformément aux recommandations de la CNIL.

#### b) Durée de conservation recommandée par la CNIL

La CNIL recommande une durée de conservation des données de journalisation de **6 mois**.

---

### Question C1.6 – Requête SQL pour M. Dinant

M. Dinant souhaite connaître le **nombre de tentatives en échec** pour chaque `type` de connexion et pour chaque `message` d'erreur :

```sql
SELECT type, message, COUNT(*) AS nb_tentatives_echec
FROM LogRescousse
WHERE resultat = 'Echec'
GROUP BY type, message
ORDER BY type, nb_tentatives_echec DESC;
```

> Le `GROUP BY type, message` permet d'obtenir le nombre d'échecs par combinaison type/message. Le `ORDER BY` est optionnel mais améliore la lisibilité.

---

*Correction réalisée sur la base du sujet BTS SIO SLAM – U6 Cybersécurité – Session 2024 (Code sujet : 24SI6SLAM-M1)*
