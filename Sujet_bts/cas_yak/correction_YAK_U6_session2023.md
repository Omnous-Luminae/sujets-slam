# Correction – Cas YAK (BTS SIO SLAM – U6 Cybersécurité) – Session 2023

> Corrigé rédigé à partir du fichier texte fourni dans la conversation (`23SI6SLAM-NC1_YAK_Sujet_BAT_2023.txt`).  
> Certaines annexes annoncées ne sont pas visibles dans l’extrait (ex. schéma relationnel complet Dossier B – doc B1, matrice EBIOS – doc B5). Lorsque ces informations manquent, des hypothèses raisonnables sont indiquées.

---

## DOSSIER A – Authentification et habilitations de l’application Holy

### Mission A1 – Bonnes pratiques pour la classe `Utilisateur`

#### A1.1 – Corriger les erreurs de nommage dans `ancienMdp`

Dans `ancienMdp`, plusieurs points ne respectent pas les bonnes pratiques Java (doc A5) :

- Paramètre `m` : non descriptif → à renommer (ex. `mdp` ou `motDePasse`).
- Variable `existe` : ok, mais on peut préférer `trouve` / `estPresent` (plus clair).
- Boucle `while` : style correct mais améliorable (condition `existe == false` → `!existe`).
- `i = i + 1` → `i++`.

Proposition conforme :

```java
public boolean ancienMdp(String motDePasse) {
    boolean trouve = false;
    int i = 0;

    while (i < this.lesAnciensMdp.size() && !trouve) {
        if (this.lesAnciensMdp.get(i).getValMdp().equals(motDePasse)) {
            trouve = true;
        } else {
            i++;
        }
    }
    return trouve;
}
```

> Remarque : encore mieux en Java moderne : une boucle `for` + `return true` dès qu’on trouve.

---

#### A1.2 – Proposer une documentation Javadoc pour `ancienMdp`

```java
/**
 * Vérifie si le mot de passe passé en paramètre fait partie des anciens mots de passe
 * déjà utilisés par l'utilisateur.
 *
 * @param motDePasse mot de passe à rechercher dans l'historique
 * @return true si le mot de passe a déjà été utilisé, false sinon
 */
public boolean ancienMdp(String motDePasse) {
    ...
}
```

---

### Mission A2 – Authentification : validation des mots de passe

#### A2.1 – Complexité attendue des mots de passe

La méthode `verifierMdp(String mdp)` donne explicitement les règles.

Elle valide si :

- longueur **≥ 12**
- au moins **1 majuscule** (`nb1 >= 1`)
- au moins **3 minuscules** (`nb2 >= 3`)
- au moins **4 chiffres** (`nb3 >= 4`)
- au moins **1 caractère spécial** parmi :
  - ASCII 33 à 46 inclus (`! " # $ % & ' ( ) * + , - .`)
  - ou `@` (ASCII 64)

Donc un mot de passe conforme doit contenir **au minimum** : 12 caractères, 1 majuscule, 3 minuscules, 4 chiffres, 1 spécial (dans la plage indiquée).

---

#### A2.2 – Écrire le code de `modifierMdp`

Règles de l’énoncé :

- Le nouveau mdp doit :
  1) respecter `verifierMdp(valMdp)`
  2) ne pas appartenir aux anciens mots de passe (`ancienMdp(valMdp)` doit être faux)
- Si ok :
  - enregistrer le mot de passe actuel comme ancien mdp avec la date du jour (`LocalDate.now()`)
  - modifier le mot de passe actuel
- Retourne `true` si modifié, sinon `false`

Proposition :

```java
public boolean modifierMdp(String valMdp) {
    boolean ok = false;

    // 1) complexité
    if (this.verifierMdp(valMdp)) {

        // 2) pas dans les anciens
        if (!this.ancienMdp(valMdp)) {

            // sauvegarder l'actuel dans l'historique
            MotDePasse ancien = new MotDePasse(this.motDePasse, LocalDate.now());
            this.lesAnciensMdp.add(ancien);

            // modifier le mot de passe courant
            this.motDePasse = valMdp;

            ok = true;
        }
    }
    return ok;
}
```

> Remarques :
> - On suppose que `this.motDePasse` contient le mdp courant (cf. attribut `motDePasse`).
> - En production, on ne stockerait pas des mots de passe en clair : on stockerait un hash + sel (mais ici, exercice).

---

### Mission A3 – Validation de l’authentification + habilitations

#### A3.1 – Ajouter un test unitaire `verifModifierMdp`

Dans `init()` :
- mdp initial : "Coe8@MatH279" (ne respecte pas forcément la règle ≥12, mais il sert de valeur initiale)
- puis on appelle :
  - `modifierMdp("Lae99_Mat00!")`
  - `modifierMdp("M1ue@uiT455n")`

La méthode `verifModifierMdp` doit tester :
- qu’un mot de passe valide et nouveau est accepté
- qu’un ancien mot de passe est refusé
- qu’un mot de passe non conforme est refusé

Proposition :

```java
@Test
void verifModifierMdp() {
    // 1) un mdp valide et nouveau => true
    assertTrue("La modification devrait réussir",
            unUtilisateur.modifierMdp("Abc12def34@Ghi"));

    // 2) un mot de passe déjà utilisé (ancien) => false
    assertFalse("Un ancien mot de passe ne doit pas être réutilisé",
            unUtilisateur.modifierMdp("Lae99_Mat00!"));

    // 3) mdp trop faible (ex : trop court) => false
    assertFalse("Un mot de passe non conforme doit être refusé",
            unUtilisateur.modifierMdp("abc"));
}
```

> Hypothèse : `verifierMdp` considère bien "Abc12def34@Ghi" conforme (≥12, 1 maj, ≥3 min, ≥4 chiffres, 1 spécial @).

---

#### A3.2 – Scénario de risque sans restriction d’accès au menu

Scénario de risque (exemple) :

- **Source de menace** : un employé de Yak-à-Partir (ou un compte compromis).
- **Événement redouté** : accès à des fonctionnalités administratives/comptables sans habilitation.
- **Vulnérabilité** : tous les éléments du menu sont visibles et accessibles, sans filtrage selon le niveau d’habilitation.
- **Impact** :
  - altération de documents (contrats, factures),
  - divulgation d’informations sensibles (données clients, informations financières),
  - fraude interne (modification de montants, suppression de pièces),
  - perte de confiance / risque juridique (RGPD si données personnelles consultées).

Exemple concret : un utilisateur “standard” accède au menu “Édition comptable” et exporte/modifie des données comptables qui ne le concernent pas.

---

#### A3.3 – Habilitation : `getNiveauHabilitation` + constructeur `AppliHoly`

**a) `getNiveauHabilitation`**

D’après `Habilitation`, on a `getNiveau()`.  
Donc :

```java
public int getNiveauHabilitation() {
    return this.sonHabilitation.getNiveau();
}
```

**b) Compléter le constructeur de `AppliHoly`**

Objectif : rendre accessibles les éléments dont le niveau requis est ≤ niveau utilisateur.

Hypothèses :
- `lesElementsMenu` est déjà instanciée et remplie.
- `ElementMenu` a `getNiveauHabilitation()` et `rendreAccessible()`.

Code :

```java
// niveau de l'utilisateur connecté
int niveauUtil = leUtilConnecte.getNiveauHabilitation();

// rendre accessibles les menus autorisés
for (ElementMenu unElement : lesElementsMenu) {
    if (unElement.getNiveauHabilitation() <= niveauUtil) {
        unElement.rendreAccessible();
    }
}
```

---

## DOSSIER B – Sécurisation de la fusion des bases de données

### Mission B1 – Sécuriser les données personnelles

#### B1.1 – Tableau demandé par Mme Lenvy (données personnelles/sensibles)

Le document B3 demande : « réaliser un tableau présentant les données personnelles et sensibles existantes dans chacune des deux bases ».  
Or, on n’a dans l’extrait que :
- pour EchapBox : structure `Client` (doc B2)
- pour Désir d’Ailleurs : schéma relationnel (doc B1) **non visible dans le texte**.

Donc je fournis un tableau **partiel** basé sur ce qu’on a + une méthode.

Proposition de tableau (partie EchapBox certaine) :

| Base | Table/Champ | Type de donnée | Catégorie |
|------|-------------|----------------|----------|
| EchapBox | Client.id | identifiant | personnelle (indirecte) |
| EchapBox | civilité, nom, prénom | identité | personnelle |
| EchapBox | dateNaiss | date de naissance | personnelle |
| EchapBox | pseudo | identifiant de compte | personnelle |
| EchapBox | mdp | authentification | donnée de sécurité (à protéger fortement) |
| EchapBox | adresse, codePostal, ville, pays | coordonnées postales | personnelle |
| EchapBox | tél, mél | coordonnées | personnelle |

Désir d’Ailleurs : à compléter à partir du doc B1 (non fourni ici).  
Méthode : lister tables contenant identité, coordonnées, préférences, informations de voyage (qui peuvent révéler des éléments sensibles selon contexte), etc.

> Note : « données sensibles » (RGPD art. 9) = santé, opinions, religion, biométrie, etc. Ici, a priori il n’y en a pas explicitement dans B2, mais cela dépend de B1.

---

#### B1.2 – Requête ALTER TABLE (ajout `accordPubli` booléen défaut FAUX)

MySQL :

```sql
ALTER TABLE Client
ADD accordPubli BOOLEAN NOT NULL DEFAULT FALSE;
```

Si on veut être explicite :

```sql
ALTER TABLE EchapBox.Client
ADD accordPubli TINYINT(1) NOT NULL DEFAULT 0;
```

---

#### B1.3 – Corps du courriel (consentement éclairé)

Éléments indispensables (RGPD) :
- identité du responsable de traitement (Yak-à-Partir / Mme Lenvy)
- finalité (démarchage commercial/publipostage)
- base légale (consentement)
- caractère facultatif (pas de réponse = pas de consentement)
- durée (1 mois pour répondre, et info conservation)
- lien vers le formulaire
- possibilité de retrait du consentement
- droits RGPD (accès, rectification, effacement, limitation, opposition, etc.)
- contact DPO / contact

Proposition (corps) :

Objet : Recueil de votre consentement pour l’envoi d’offres commerciales (EchapBox)

Bonjour,  
Dans le cadre de l’évolution de nos services, nous procédons à une fusion technique des bases de données de nos applications **EchapBox** et **Désir d’Ailleurs**.  
Cette opération n’a pas d’impact sur votre utilisation d’EchapBox, mais elle nous amène à vous demander votre accord explicite si vous souhaitez recevoir des offres et informations commerciales par publipostage.

**Finalité** : utilisation de vos coordonnées pour vous adresser des communications commerciales (offres EchapBox/Yak-à-Partir).  
**Base légale** : votre **consentement**.

Le consentement est **facultatif** :
- si vous ne souhaitez pas recevoir ces communications, vous n’avez rien à faire (par défaut, votre accord est **désactivé**) ;
- si vous souhaitez les recevoir, vous pouvez donner votre accord via le formulaire suivant :  
https://www.EchapBox.com/accordPubli

Vous disposez d’un délai d’**un mois** pour répondre.

Vous pourrez **retirer votre consentement à tout moment** (depuis votre compte ou en nous contactant), ce qui mettra fin aux envois.

Conformément au RGPD, vous disposez de droits sur vos données (accès, rectification, effacement, limitation, opposition, etc.).  
Pour toute question ou demande : [adresse e‑mail de contact / DPO].

Cordialement,  
Yak-à-Partir / EchapBox  
[coordonnées de l’entreprise]

---

#### B1.4 – Conserver une trace du consentement + garantir son intégrité

Objectif : preuve + intégrité.

Solution détaillée (exemple robuste) :

1) **Journaliser l’acte de consentement** dans une table dédiée (preuve) :
   - `idConsentement` (PK)
   - `idClient`
   - `dateHeureConsentement`
   - `canal` (web)
   - `versionTexteInformation` (version du texte présenté)
   - `ip` / `userAgent` (optionnel, à proportionner)
   - `valeur` (TRUE/FALSE, ici TRUE quand l’utilisateur coche/valide)

2) **Garder la version du texte** affiché :
   - stocker le texte ou un identifiant de version + conserver le document exact (PDF/HTML figé).

3) **Garantir l’intégrité** :
   - calculer un **hash** (SHA-256) de l’enregistrement + du texte/version, stocké dans la table, ou
   - signer numériquement (clé privée) le hash et stocker la signature, ou
   - chaîner les logs (hash chain) : chaque enregistrement contient le hash du précédent.
   - idéalement stocker dans un système **WORM** / coffre-fort numérique / journaux immuables.

4) **Traçabilité et contrôle d’accès** :
   - accès restreint (admin/DPO),
   - journaliser les accès à ces preuves.

Cette solution permet :
- de prouver que le client a consenti,
- de prouver **à quoi** il a consenti (texte/version),
- de détecter toute altération (intégrité).

---

#### B1.5 – Structure de `ClientAnonyme` après minimisation

Objectif : statistiques (genre, tranche d’âge, département) sans conserver plus que nécessaire.

On peut donc éviter nom/prénom/adresse complète/tél/mél et conserver :
- `idClientAnonyme` (PK)
- `civilite` ou `genre` (si utile)
- `anneeNaissance` ou `trancheAge`
- `departement` (extrait de `codePostal`, ex. 2 premiers chiffres)
- éventuellement `dateCreation`/`dateInscription` (si stats temporelles)

Formalisme doc B2 :

`ClientAnonyme(idAnon, genre, trancheAge, departement)`

Exemple plus détaillé :

`ClientAnonyme(idAnon, civilite, anneeNaiss, departement)`

> Remarque RGPD : on anonymise réellement si on ne peut plus ré-identifier.  
> Si `idAnon` reste lié à `id` via une table de correspondance, on est plutôt en **pseudonymisation**.

---

### Mission B2 – Détecter les agissements frauduleux

#### B2.1 – Justifier la gravité de R1 et R2

- **R1 (acompte ≥ montant à payer)** :
  - Impact financier direct : perte de chiffre d’affaires (contrat “soldé” par acompte artificiel).
  - Fraude possible (paiement restant = 0 ou négatif), erreurs comptables.
  - Impact réputation / litiges.
  - Donc gravité élevée (perte financière + fraude).

- **R2 (montant < minimum 75€/pers/jour)** :
  - Impact financier : sous-facturation / marge négative.
  - Peut être exploité à grande échelle si injection SQL automatisée.
  - Peut compromettre la pérennité, créer des erreurs comptables et fiscales.
  - Gravité élevée également, possiblement un peu moindre que R1 selon politique (mais dépend de la matrice doc B5).

Sans la matrice B5, on justifie qualitativement : atteinte à l’intégrité des données + pertes financières.

---

#### B2.2 – Requête : clients ayant acompte ≥ montant à payer

Sans doc B1, on doit supposer les tables et clés.  
On sait qu’il existe `Contrat_Voyage` et probablement une table `Client` et un lien.

Hypothèse typique :
- `Client(idCli, nom, prenom, ...)`
- `Contrat_Voyage(idContrat, idCli, montantAPayer, acompteVerse, ...)`

Requête :

```sql
SELECT c.idCli, c.nom, c.prenom
FROM Client c
JOIN Contrat_Voyage cv ON cv.idCli = c.idCli
WHERE cv.acompteVerse >= cv.montantAPayer;
```

Si les noms de champs diffèrent, adapter selon le schéma réel (doc B1).

---

#### B2.3 – Compléter le trigger : minimum 75€/participant/jour

Le trigger vérifie déjà que `nbJours >= 3` via `Devis_Voyage.nbJours`.

Il manque la règle :
> montant à payer minimal = 75 € * nbParticipants * nbJours

On a besoin :
- nbJours (`@nb_jours`)
- nbParticipants (probablement dans `Devis_Voyage` ou dans `Contrat_Voyage`)
- montant à payer (probablement `NEW.montantAPayer` ou équivalent)

Hypothèse :
- `Devis_Voyage` contient `nbParticipants`
- `Contrat_Voyage` contient `montantAPayer`

Ajout :

```sql
-- récupérer nbParticipants
SET @nb_participants = (
    SELECT nbParticipants
    FROM Devis_Voyage
    WHERE idDevis = NEW.idDevis
);

-- calcul du minimum
SET @min_montant = 75 * @nb_participants * @nb_jours;

IF NEW.montantAPayer < @min_montant THEN
    SIGNAL SQLSTATE '10002';
    SET MESSAGE_TEXT = 'Montant inférieur au minimum (75 euros par participant et par jour)';
END IF;
```

> Si le champ s’appelle `montantAPayer` autrement, adapter.

---

## DOSSIER C – Amélioration de la sécurité des applications Web

### Mission C1 – Vérifier la protection contre CSRF

#### C1.1 – Fonctionnement de la protection CSRF mise en place

Dans `modifMdp.php` :

- on démarre la session (`session_start()`)  
- on récupère un token de session : `$token = $_SESSION['token'];`
- on l’inclut dans le formulaire via un champ caché.

Dans `traitement.php` :

- on démarre la session  
- on vérifie que le token de session et celui reçu en POST existent et sont égaux.

**Principe** :
- Une attaque CSRF s’appuie sur le fait que le navigateur envoie automatiquement les cookies de session.
- Le token anti‑CSRF est un secret (lié à la session) que l’attaquant ne peut pas deviner ; il doit être présent dans la requête.
- Si le token ne correspond pas, le serveur refuse l’action.

---

### Mission C2 – Analyse des fichiers de journalisation

#### C2.1 – Analyse de l’extrait de logs

**a) Événements présents**

- AllanG : erreur de connexion
- essai de connexion avec champs vides
- RichardP : erreurs de connexion en rafale (plusieurs fois)
- AllanG : connexion réussie
- RichardP : erreurs de connexion (encore)

**b) Hypothèse (note au responsable)**

L’événement remarquable est la succession d’échecs très rapprochés pour RichardP.  
Hypothèse : tentative de **force brute** / **credential stuffing** / script automatisé.  
Actions : vérifier IP, mettre en place limitation d’essais/verrouillage temporaire.

---

#### C2.2 – Évolution de la base pour enregistrer les tentatives de connexion

**a) Proposition d’évolution**

Ajouter une table `TentativeConnexion` :
- `idTentative` (PK)
- `idCli` (FK vers Client)
- `dateHeure` (DATETIME)
- `resultat` (SUCCES/ECHEC)

Optionnel : `ipSource`, `userAgent`.

**b) Deux enregistrements pour un même utilisateur**

Exemple (idCli=12) :
- (1, 12, '2023-05-10 21:41:24', 'ECHEC')
- (2, 12, '2023-05-10 21:41:26', 'ECHEC')

---

#### C2.3 – Solution technique pour désactiver temporairement le compte

- Ajouter `estActif` (BOOLEAN) ou `statut` dans `Client`.
- Sur seuil d’échecs (ex. 5 en 5 minutes) : `estActif=false` (suspension).
- Déblocage : automatique après délai, ou manuel par admin.
- Compléments : rate limiting, CAPTCHA, MFA.