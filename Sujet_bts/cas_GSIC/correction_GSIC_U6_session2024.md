# Correction – Cas GSIC (BTS SIO SLAM – U6 Cybersécurité) – Session 2024

> Remarque : ce corrigé est rédigé à partir du texte fourni dans la conversation. Certains éléments annoncés dans le sujet (diagramme BdInventaire – doc A3, captures Postman / extrait table Formations – doc B7, diagramme de classes complet – doc C1) ne sont pas présents ici ; lorsque c’est bloquant, je propose une réponse cohérente et j’indique les hypothèses.

---

## DOSSIER A – Préparation de la mise en place d’une authentification unique (SSO)

### A1 – Fichiers actuels de journalisation des authentifications

#### A1.1 – Objectif réglementaire de la traçabilité des accès

L’objectif réglementaire de la traçabilité des accès (journalisation) est de :

- **détecter et analyser** les événements de sécurité (accès non autorisés, tentatives d’intrusion, usurpations) ;
- **prouver** qu’un accès / une action a eu lieu (non-répudiation « pratique » : éléments de preuve) ;
- **répondre aux obligations de sécurité** liées aux traitements de données (exigence d’accountability du RGPD, obligations de sécurité, et bonnes pratiques type ANSSI/CNIL) ;
- permettre les **investigations** (forensique) et la **reconstruction** d’un incident.

En synthèse : *identifier qui a fait quoi, quand, depuis quel équipement / quel contexte*, pour pouvoir sécuriser et auditer.

#### A1.2 – Archivage vs sauvegarde, et intérêt de l’archivage des journaux

**a) Différence d’objectif**

- **Sauvegarde** : objectif principal = **restauration** après incident (panne, suppression accidentelle, chiffrement ransomware). On cherche à retrouver l’état des données.
- **Archivage** : objectif principal = **conservation sur la durée** (souvent figée), pour des besoins **légaux, probatoires, historiques** et d’audit. On cherche à conserver des traces, pas à « revenir en arrière ».

**b) Pourquoi archiver les fichiers de logs d’authentification ?**

Les journaux d’authentification sont archivés afin de :

- disposer d’un **historique** en cas d’enquête interne / judiciaire ;
- **corréler** des événements sur plusieurs semaines/mois (ex : attaques « low and slow ») ;
- démontrer la **conformité** (contrôle interne, audits, exigences PSSI).

#### A1.3 – Confidentialité et intégrité lors de l’archivage : sont-elles garanties ?

**Confidentialité : plutôt oui** (mais à nuancer)

- Les journaux sont **compressés avec chiffrement** avant transfert sur bandes : si le chiffrement est correctement mis en œuvre (algorithme robuste, gestion de clés correcte), la confidentialité est assurée pendant le transport et au repos sur bande.
- Point de vigilance : la confidentialité dépend fortement de la **gestion des clés** (stockage, rotation, contrôle d’accès). Le sujet ne donne pas ces détails.

**Intégrité : non, pas pleinement garantie**

- Il est explicitement indiqué : **« sans vérification des sommes de contrôles (empreinte numérique) »**.
- Sans empreinte (hash) et sans mécanisme de signature / scellement, on ne peut pas prouver qu’un fichier archivé n’a pas été altéré entre la création et la consultation, ni détecter une corruption.

Conclusion : **confidentialité vraisemblablement assurée par le chiffrement**, mais **intégrité non garantie** car absence de contrôle d’empreinte (idéalement : hash + signature, ou stockage WORM / coffre-fort numérique, ou chaîne de hachage).

---

### A2 – Inventaire des comptes d’authentification existants

#### A2.1 – Vue `v_liste_comptes`

Objectif : obtenir un flux unifié avec le schéma :

`v_liste_comptes (origine, nom, prenom, compte_login, roles)`

Données sources :

- **Personnel.Compte_Employe** : `login`, `nomUser`, `prenomUser`, `rolesUser`
- **Formation.Utilisateur** : `compte`, `nom`, `prenom` (pas de rôles)
- **Logistique.Compte** : `compte`, `nom_compte`, `prenom_compte`, `roles_compte`
- **Prevention.User** : `login`, `nom`, `prenom`, `role`

Vue (MySQL) :

```sql
CREATE OR REPLACE VIEW BdInventaire.v_liste_comptes
(origine, nom, prenom, compte_login, roles)
AS
SELECT
  'Personnel'        AS origine,
  ce.nomUser         AS nom,
  ce.prenomUser      AS prenom,
  ce.login           AS compte_login,
  ce.rolesUser       AS roles
FROM Personnel.Compte_Employe ce

UNION

SELECT
  'Formation'        AS origine,
  u.nom              AS nom,
  u.prenom           AS prenom,
  u.compte           AS compte_login,
  NULL               AS roles
FROM Formation.Utilisateur u

UNION

SELECT
  'Logistique'       AS origine,
  c.nom_compte       AS nom,
  c.prenom_compte    AS prenom,
  c.compte           AS compte_login,
  c.roles_compte     AS roles
FROM Logistique.Compte c

UNION

SELECT
  'Prevention'       AS origine,
  pu.nom             AS nom,
  pu.prenom          AS prenom,
  pu.login           AS compte_login,
  pu.role            AS roles
FROM Prevention.User pu;
```

> Remarque : `UNION` supprime les doublons ; si on souhaite conserver toutes les lignes sans déduplication, utiliser `UNION ALL`.

#### A2.2 – Compléter la modélisation BdInventaire

Sans le document A3, on propose une modélisation minimale permettant à InventaireHabil :

- d’enregistrer les comptes,
- d’identifier l’application à partir de `origine`,
- de gérer les **rôles multiples** (Personnel/Logistique : rôles séparés par virgules),
- de n’attribuer un identifiant à chaque rôle que s’il est rattaché à **une seule application**.

Proposition (tables relationnelles) :

- **Application**(`idApp` PK, `nom` UNIQUE)  
  Ex : Personnel, Formation, Logistique, Prevention
- **Compte**(`idCompte` PK, `login`, `nom`, `prenom`, `idApp` FK→Application)
- **Role**(`idRole` PK, `libelle`, `idApp` FK→Application)  
  Un rôle appartient à une seule application.
- **CompteRole**(`idCompte` FK→Compte, `idRole` FK→Role, PK(`idCompte`,`idRole`))

Cette structure permet :

- 1 compte → 0..n rôles,
- un rôle → 1 application,
- et la normalisation de la liste de rôles initialement « CSV ».

#### A2.3 – Compte MySQL `prep_sso` et droits minimaux

**a) Création du compte** (utilisation locale, comme demandé) :

```sql
CREATE USER 'prep_sso'@'localhost' IDENTIFIED BY 'MotDePasseRobuste_AChanger';
```

**b) Droits strictement nécessaires**

Le programme InventaireHabil :

- lit la vue `BdInventaire.v_liste_comptes` → nécessite des droits `SELECT` sur la vue (et potentiellement sur les tables sous-jacentes selon le mode de sécurité / definer).
- insère dans les tables de BdInventaire → nécessite `INSERT` (et éventuellement `SELECT` si contrôles d’existence / déduplication).

Proposition minimale (à adapter aux tables exactes de BdInventaire) :

```sql
-- lecture de la vue
GRANT SELECT ON BdInventaire.v_liste_comptes TO 'prep_sso'@'localhost';

-- écriture dans les tables d’inventaire (exemples)
GRANT SELECT, INSERT, UPDATE ON BdInventaire.Compte TO 'prep_sso'@'localhost';
GRANT SELECT, INSERT, UPDATE ON BdInventaire.Role TO 'prep_sso'@'localhost';
GRANT SELECT, INSERT, DELETE ON BdInventaire.CompteRole TO 'prep_sso'@'localhost';
GRANT SELECT, INSERT, UPDATE ON BdInventaire.Application TO 'prep_sso'@'localhost';
```

> Principe : **moindre privilège**. Si l’application ne fait que `INSERT` sans mise à jour, retirer `UPDATE/DELETE`.

---

## DOSSIER B – Mise en place du service SSO pour le système de gestion administratif

### B1 – Renforcer la sécurité des données personnelles et sensibles

#### B1.1 – Divulgation d’identifiants à un stagiaire

**a) Infractions commises par l’agent**

- Violation de la **charte informatique** : « ne jamais communiquer ses codes d’accès à un tiers ».
- Mise en danger de la sécurité du SI (manquement à une obligation professionnelle de sécurité).
- Potentiellement, participation à un accès frauduleux (au minimum : **facilitation** d’accès non autorisé).

**b) Le stagiaire est-il en faute ?**

Oui si :

- le stagiaire utilise un compte qui n’est pas le sien (usurpation),
- ou accède à des ressources sans autorisation explicite.

Même si l’identifiant/mot de passe a été donné, cela ne constitue pas une autorisation valable : l’accès doit être **personnel** et **attribué**.

**c) Risques encourus**

- **Disciplinaires** : avertissement, suspension d’accès, sanctions selon règlement.
- **Civils / pénaux** (selon faits, intention, préjudice) : accès frauduleux à un système, atteinte à l’intégrité/confidentialité de données, etc.
- **Organisationnels** : compromission de données, traçabilité faussée (« qui a fait quoi »), fuite d’informations, non-conformité RGPD.

#### B1.2 – Condition pour que la charte s’impose aux employés

Pour être opposable aux salariés, la charte doit être :

- **portée à la connaissance** des personnels (diffusion, remise, signature/accusé de réception),
- et, lorsqu’elle a valeur de règlement intérieur/annexe : **respecter les règles de dépôt/consultation** applicables (CSE, inspection du travail, affichage, etc.).

Idée clé attendue : **elle doit être intégrée/annexée au règlement intérieur ou soumise au même régime et notifiée** ; sinon, elle est difficilement opposable.

#### B1.3 – Données sensibles dans la base `Medical`

D’après le doc B3 :

- `num_secu` (NIR) → donnée personnelle à haut risque.
- Données d’identité : `nom`, `prenom`, `date_naissance`, `pays_naissance`.
- Coordonnées : `tel_priv`, `tel_prof`, `mail_prof`, `rue`, `complement_rue`, `code_postal`, `ville`.
- Données liées à la santé / suivi médical (sensibles au sens RGPD) :
  - dans `Visite` : `taille`, `poids`, `masse_graisseuse`, `masse_musculaire`, `tension`, `profil`.
  - dans `Vaccination` (et liaison avec `Vaccin.nom`) : information de vaccination.

> Le doc précise : **Rhésus non considéré sensible** dans ce contexte (inscrit en clair sur uniforme dans certains corps). On l’exclut donc des « sensibles » attendues.

#### B1.4 – Scénario de risque rendant pertinent le chiffrement (accès applicatif sécurisé)

Même si l’application chiffre les échanges et authentifie correctement :

- un attaquant obtient un **accès au serveur SQL** (compte admin compromis, vulnérabilité OS, vol de sauvegardes, snapshot VM, accès d’un prestataire) ;
- ou exfiltre des fichiers `.mdf/.ldf` / sauvegardes.

Sans chiffrement colonne : les données sont lisibles **hors application**. 
Le chiffrement en base réduit l’impact d’une compromission du stockage/backup (confidentialité) et limite l’exposition en cas d’accès « lecture seule » non autorisé.

#### B1.5 – Tester le point 4 (chiffrement) sur `PatientAnonyme.rhesus`

Point 4 du scénario : ajouter colonne chiffrée, remplir, supprimer clair, renommer.

Exemple T‑SQL (en supposant qu’on chiffre `rhesus` malgré la remarque, pour l’exercice) :

```sql
-- 4a) ajouter colonne varbinary
ALTER TABLE PatientAnonyme
ADD rhesus_tmp VARBINARY(30);
GO

-- ouverture de la clé pour pouvoir chiffrer
OPEN SYMMETRIC KEY Medical_Key
DECRYPTION BY CERTIFICATE Medical18;
GO

-- 4b) renseigner avec la donnée chiffrée
UPDATE PatientAnonyme
SET rhesus_tmp = EncryptByKey(Key_GUID('Medical_Key'), CONVERT(NVARCHAR(30), rhesus));
GO

CLOSE SYMMETRIC KEY Medical_Key;
GO

-- 4c) supprimer la colonne en clair
ALTER TABLE PatientAnonyme
DROP COLUMN rhesus;
GO

-- 4d) renommer la colonne chiffrée
EXEC sp_rename 'PatientAnonyme.rhesus_tmp', 'rhesus', 'COLUMN';
GO

-- Test lecture brute : on voit du varbinary (donc du chiffré)
SELECT TOP(10) id_anonyme, rhesus FROM PatientAnonyme;
```

---

### B2 – Audit de sécurité et intégration

#### B2.1 – Conséquences si aucune route API n’est soumise à authentification

Si l’API ne contrôle pas elle-même l’authentification/autorisation :

- Toute personne sur le réseau pouvant appeler l’API peut invoquer **GET/POST/PUT/DELETE** directement (ex : Postman), donc **contourner** l’IHM.
- Risque d’atteinte :
  - **confidentialité** (lecture formations),
  - **intégrité** (création / modification / suppression),
  - **traçabilité** (actions non attribuables à un utilisateur authentifié),
  - **élévation de privilèges**.

En bref : la sécurité « côté client » est insuffisante : **le serveur (API) doit être le point de contrôle**.

#### B2.2 – Problème de modification du « public concerné » (hypothèse la plus probable)

Sans les captures, l’hypothèse la plus fréquente sur un `PUT /formations/{code}` est :

- **incohérence entre le `{code}` dans l’URL et le `code` dans le corps JSON** (ou absence du champ),
- ou **mauvais mapping** JSON↔objet Java (champ différent, casse, nom attribut).

Solution à proposer à Élodie (méthode) :

1. Vérifier que la requête Postman envoie :
   - `PUT /formations/F204591`
   - un body JSON valide contenant *le champ attendu* (ex : `publicConcerne` ou `public`), et encodé en `application/json`.
2. Côté API : dans `mettreAJourFormation`, vérifier qu’on utilise bien :
   - le `code` du path comme identifiant de la ressource,
   - et qu’on **ne dépend pas d’un code présent dans le JSON** (ou qu’on vérifie leur égalité).

Exemple de contrôle (idée) :

```java
if (!code.equals(formation.getCode())) {
  throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Code URL différent du code JSON");
}
```

#### B2.3 – Hypothèse la plus probable sur `invalid_token` après 15 minutes

Le champ `expires_in` du JWT vaut **300 secondes = 5 minutes** (doc B6).
Après 15 minutes, l’**access token est expiré** → l’API rejette le jeton : `Token verification failed`.

Donc : il faut soit redemander un token, soit utiliser le **refresh token** pour en obtenir un nouveau.

#### B2.4 – Compléter la méthode `getToken()` (rafraîchissement)

Spécifications :

- utiliser `requestToken(params)`
- params = `refresh_token`, `client_id`, `grant_type`
- grant_type = `refresh-token` (tel qu’écrit dans l’énoncé ; en OIDC standard c’est souvent `refresh_token`)

Implémentation :

```java
public String getToken() {
  List<NameValuePair> params = new ArrayList<NameValuePair>();
  params.add(new BasicNameValuePair("refresh_token", this.refreshToken));
  params.add(new BasicNameValuePair("client_id", "gsic_api_rolebased"));
  params.add(new BasicNameValuePair("grant_type", "refresh-token"));
  this.requestToken(params);
  return this.token;
}
```

---

### B3 – Impact du SSO sur les risques établis

#### B3.1

**a) Pourquoi le SSO modifie le scénario ?**

Avec SSO, un seul mot de passe (ou un seul jeton/identité) peut donner accès à **plusieurs applications**. 
Donc, si le mot de passe est volé :

- l’attaque ne touche plus seulement Sdisform, mais potentiellement **tout le SI** fédéré (effet de **concentration du risque**).
- l’impact (gravité) augmente : accès à des données plus nombreuses, fonctions plus critiques.

**b) Piste d’amélioration pour réduire le risque**

- Mettre en place une **MFA** (authentification multifacteur) sur le SSO.
- Renforcer la détection : supervision, alertes, analyse d’anomalies.
- Appliquer le **moindre privilège** (rôles/claims limités) et une gestion fine des habilitations.
- Limiter la durée des tokens, mettre en place rotation/ révocation.

---

## DOSSIER C – Adaptation de la politique de sécurité de l’application mobile Rescousse

### C1 – Renforcement de la sécurité d’accès

#### C1.1 – Attaque mieux contrée par un mot de passe 8 caractères qu’un PIN 4 chiffres

Un mot de passe 8 caractères (selon politique : lettres/majuscules/chiffres/symboles) augmente l’espace de recherche.

Il protège mieux contre :

- l’**attaque par force brute** / essai exhaustif (en local ou en ligne),
- et le **devinage** (PIN trop court, souvent basé sur des motifs courants : 0000, 1234, date).

#### C1.2 – Différence juridique : reconnaissance faciale vs mot de passe

- Mot de passe = **connaissance** (quelque chose que l’on sait), modifiable, révocable.
- Reconnaissance faciale = **biométrie** (quelque chose que l’on est) :
  - donnée **particulière** / sensible (au sens RGPD : données biométriques utilisées pour identifier une personne de manière unique),
  - traitement soumis à **conditions renforcées** (finalité, minimisation, sécurité, base légale, information, etc.).

De plus, en cas de compromission : un visage n’est pas « réinitialisable » comme un mot de passe.

#### C1.3 – Code de `ajouterEntreeLog` (SQLite)

On insère dans la table `Log(date, heure, type, resultat, message)`.

Implémentation (en restant simple, avec `execSQL`) :

```java
public void ajouterEntreeLog(EntreeLog uneEntreeLog) {
  try {
    SQLiteDatabase db = this.getWritableDatabase();

    String sql = "INSERT INTO " + TABLE_NAME
        + " (date, heure, type, resultat, message) VALUES (?, ?, ?, ?, ?);";

    db.execSQL(
        sql,
        new Object[]{
            uneEntreeLog.getDate().toString(),
            uneEntreeLog.getHeure().toString(),
            uneEntreeLog.getType(),
            uneEntreeLog.getResultat(),
            uneEntreeLog.getMessage()
        }
    );
  } catch (Exception ex) {
    traiterErreur("insertion log", ex);
  }
}
```

> Alternative « Android standard » : utiliser `ContentValues` + `db.insert(...)`.

#### C1.4 – Compléter `onCreate` de `LoginBiometrieActivity`

On doit enregistrer un log :

- type = `LoginBiometrie`
- succès : resultat=`Succes`, message=`OK`
- erreur : resultat=`Echec`, message=`errorCode + " - " + errString`

Ajouts attendus dans les callbacks :

```java
@Override
public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
  super.onAuthenticationError(errorCode, errString);

  // log
  EntreeLog e = new EntreeLog(
      "LoginBiometrie",
      "Echec",
      errorCode + " - " + errString
  );
  dbLog.ajouterEntreeLog(e);

  // affichage
  snack(errorCode + " - " + errString);
}

@Override
public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
  super.onAuthenticationSucceeded(result);

  // log
  EntreeLog e = new EntreeLog(
      "LoginBiometrie",
      "Succes",
      "OK"
  );
  dbLog.ajouterEntreeLog(e);

  startActivity(rescousseActivite);
}
```

#### C1.5 – Contenu indispensable des logs (CNIL) et durée

**a) La table `LogRescousse` est-elle complète ?**

Recommandations CNIL (doc C4) : journaliser au minimum :

- **auteur** individuellement identifié,
- **horodatage**,
- **équipement** utilisé,
- **nature de l’opération**.

Table proposée :

- `adMAC` → équipement (OK),
- `date`, `heure` → horodatage (OK),
- `type` → nature (partielle : type d’authent),
- `resultat`, `message` → détails (OK),
- **manque un auteur identifié** (ex : `idUtilisateur` ou identifiant opérationnel). 

Donc : **non**, il manque l’auteur (ex : `idUtilisateur` ou identifiant opérationnel). 

**b) Durée de conservation recommandée**

Pour les journaux de sécurité/authentification, la CNIL recommande généralement une conservation **limitée**, souvent **6 mois** (ordre de grandeur fréquemment attendu en BTS).

> À adapter selon finalité et politique interne ; l’important est « durée proportionnée et limitée ».

#### C1.6 – Requête : nombre d’échecs par type et par message

```sql
SELECT
  type,
  message,
  COUNT(*) AS nbEchecs
FROM LogRescousse
WHERE resultat = 'Echec'
GROUP BY type, message
ORDER BY type, nbEchecs DESC;
```