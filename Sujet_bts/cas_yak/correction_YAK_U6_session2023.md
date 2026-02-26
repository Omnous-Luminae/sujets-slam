# Correction – BTS SIO Option SLAM · Session 2023 (Nouvelle-Calédonie)
## U6 – Cybersécurité des services informatiques
### Cas Yak-à-Partir

---

## DOSSIER A – Authentification et habilitations de l'application Holy

---

### Question A1.1 – Correction des erreurs de nommage de la méthode `ancienMdp`

En s'appuyant sur les règles de programmation Java (Document A5) :

**Erreurs identifiées dans la méthode `ancienMdp` :**

La méthode est nommée `ancienMdp`. D'après les bonnes pratiques Java, **une méthode doit refléter une action** et son nom doit de préférence commencer par un verbe. Le nom `ancienMdp` est un adjectif/nom, pas un verbe.

De plus, le paramètre `m` est un nom de variable composé d'une seule lettre. D'après les règles, les variables à une lettre ne sont acceptées que pour des usages locaux de boucle (`i`, `j`, `k`) ou de caractère (`c`, `d`, `e`). Pour un paramètre représentant un mot de passe, un nom descriptif est obligatoire.

**Version corrigée :**

```java
public boolean estAncienMdp(String valMdp) {
    boolean existe = false;
    int i = 0;
    while (i < this.lesAnciensMdp.size() && existe == false) {
        if (this.lesAnciensMdp.get(i).getValMdp().equals(valMdp)) {
            existe = true;
        } else {
            i = i + 1;
        }
    }
    return existe;
}
```

**Corrections effectuées :**
- `ancienMdp` → `estAncienMdp` (nom avec verbe, reflète une action : « est-ce un ancien mot de passe ? »)
- Paramètre `m` → `valMdp` (nom descriptif)

---

### Question A1.2 – Documentation Javadoc pour la méthode `estAncienMdp`

```java
/**
 * Vérifie si le mot de passe passé en paramètre fait partie
 * des anciens mots de passe de l'utilisateur.
 *
 * @param valMdp le mot de passe à vérifier
 * @return true si le mot de passe a déjà été utilisé, false sinon
 */
public boolean estAncienMdp(String valMdp) { ... }
```

---

### Question A2.1 – Complexité des mots de passe attendue

En analysant la méthode `verifierMdp` du Document A3, les règles de complexité sont les suivantes :

| Critère | Exigence minimale |
|---|---|
| Longueur totale | Au moins **12 caractères** |
| Majuscules | Au moins **1** |
| Minuscules | Au moins **3** |
| Chiffres | Au moins **4** |
| Caractères spéciaux | Au moins **1** (parmi les codes ASCII 33–46 ou le caractère `@`) |

> Les caractères spéciaux acceptés (codes ASCII 33 à 46) correspondent à : `! " # $ % & ' ( ) * + , - .` ainsi que `@` (code 64).

---

### Question A2.2 – Code de la méthode `modifierMdp`

D'après la Javadoc fournie dans le Document A3 :
- Vérifier la complexité du nouveau mot de passe via `verifierMdp()`.
- Vérifier que le nouveau mot de passe ne fait pas partie des anciens via `estAncienMdp()`.
- Si les deux vérifications passent : enregistrer le mot de passe actuel comme ancien mot de passe (avec la date du jour), puis remplacer le mot de passe actuel.
- Retourner `true` si la modification a réussi, `false` sinon.

```java
public boolean modifierMdp(String valMdp) {
    boolean resultat = false;

    if (verifierMdp(valMdp) && !estAncienMdp(valMdp)) {
        // Enregistrement de l'ancien mot de passe avec la date du jour
        MotDePasse ancienMotDePasse = new MotDePasse(this.motDePasse, LocalDate.now());
        this.lesAnciensMdp.add(ancienMotDePasse);

        // Mise à jour du mot de passe actuel
        this.motDePasse = valMdp;

        resultat = true;
    }

    return resultat;
}
```

---

### Question A3.1 – Méthode de test `verifModifierMdp`

En s'appuyant sur le Document A4 (classe `UtilisateurTest`) et sur le comportement attendu de `modifierMdp` :

```java
@Test
void verifModifierMdp() {
    // Cas 1 : nouveau mot de passe valide et non utilisé → doit retourner true
    assertTrue("Erreur : modification avec mdp valide doit retourner true",
        unUtilisateur.modifierMdp("Tr0uV@ille99X"));

    // Cas 2 : mot de passe trop simple (ne respecte pas les règles de complexité)
    // → doit retourner false
    assertFalse("Erreur : modification avec mdp trop simple doit retourner false",
        unUtilisateur.modifierMdp("simple"));

    // Cas 3 : mot de passe déjà utilisé (présent dans lesAnciensMdp)
    // "M1ue@uiT455n" a été utilisé dans le @BeforeEach
    assertFalse("Erreur : modification avec un ancien mdp doit retourner false",
        unUtilisateur.modifierMdp("M1ue@uiT455n"));
}
```

> Remarque : d'après le `@BeforeEach`, l'utilisateur a successivement utilisé `"Coe8@MatH279"` (mot de passe initial), `"Lae99_Mat00!"` (1ère modif), et `"M1ue@uiT455n"` (2ème modif). Ces deux derniers sont dans `lesAnciensMdp`.

---

### Question A3.2 – Scénario de risque lié à l'absence de restriction des éléments du menu

**Scénario de risque :**

Un utilisateur dispose d'un compte dans l'application Holy avec un niveau d'habilitation faible (par exemple, un stagiaire avec le rôle « lecture seule »). En l'absence de restriction des éléments du menu selon le niveau d'habilitation, **tous les éléments du menu sont visibles et accessibles** pour cet utilisateur.

Ce dernier pourrait alors accéder aux fonctionnalités de gestion comptable (génération de contrats, modification des tarifs, suppression de données clients) qui ne lui sont normalement pas destinées. Il pourrait ainsi, intentionnellement ou non :
- **Modifier ou supprimer des contrats** existants, causant un préjudice financier à l'entreprise.
- **Consulter des données confidentielles** (coordonnées bancaires, données personnelles des clients) auxquelles il ne devrait pas avoir accès.

Ce scénario constitue une violation du **principe du moindre privilège** et représente un risque de **perte d'intégrité des données** et d'**atteinte à la confidentialité**.

---

### Question A3.3

#### a) Code de la méthode `getNiveauHabilitation`

D'après le diagramme de classes (Document A1), `Utilisateur` possède un attribut `sonHabilitation` de type `Habilitation`, et la classe `Habilitation` dispose d'une méthode `getNiveau()`.

```java
/** @return le niveau de l'habilitation de l'utilisateur */
public int getNiveauHabilitation() {
    return sonHabilitation.getNiveau();
}
```

#### b) Complétion du constructeur de la classe `AppliHoly`

D'après les spécifications : seuls les éléments du menu dont le `niveauHabilitation` est **inférieur ou égal** au niveau de l'utilisateur connecté doivent être rendus accessibles.

```java
public AppliHoly(Utilisateur unUtil) throws HeadlessException {
    // ... instanciation des composants graphiques (code non fourni) ...

    leUtilConnecte = unUtil;

    // Rendre accessibles les éléments du menu autorisés
    for (ElementMenu element : lesElementsMenu) {
        if (element.getNiveauHabilitation() <= leUtilConnecte.getNiveauHabilitation()) {
            element.rendreAccessible();
        }
    }
}
```

---

## DOSSIER B – Sécurisation de la fusion des bases de données

---

### Question B1.1 – Tableau des données personnelles et sensibles

En s'appuyant sur le Document B1 (schéma BDD Désir d'Ailleurs) et le Document B2 (table Client EchapBox) :

**Définitions RGPD rappelées :**
- **Donnée personnelle** : toute information permettant d'identifier directement ou indirectement une personne physique.
- **Donnée sensible** : catégorie particulière de données personnelles (origine raciale/ethnique, opinions politiques, données de santé, données biométriques, etc.) nécessitant une protection renforcée.

| Champ | Base Désir d'Ailleurs | Base EchapBox | Type |
|---|:---:|:---:|---|
| nom | ✓ | ✓ | Donnée personnelle |
| prénom | ✓ | ✓ | Donnée personnelle |
| dateNaiss | ✓ | ✓ | Donnée personnelle |
| pseudo | ✓ | ✓ | Donnée personnelle |
| mdp | ✓ | ✓ | Donnée personnelle |
| adresse | ✓ | ✓ | Donnée personnelle |
| codePostal | ✓ | ✓ | Donnée personnelle |
| ville | ✓ | ✓ | Donnée personnelle |
| pays | ✓ | ✓ | Donnée personnelle |
| tél | ✓ | ✓ | Donnée personnelle |
| mél | ✓ | ✓ | Donnée personnelle |
| civilité | ✓ | ✓ | Donnée personnelle |
| numPièceIdentité | ✓ | — | Donnée personnelle |
| typePièceIdentité | ✓ | — | Donnée personnelle |
| nationalité | ✓ | — | Donnée **sensible** (origine) |
| estAMobilitéRéduite | ✓ | — | Donnée **sensible** (santé/handicap) |

---

### Question B1.2 – Requête pour modifier la table Client (EchapBox)

```sql
ALTER TABLE Client
ADD accordPubli BOOLEAN DEFAULT FALSE;
```

---

### Question B1.3 – Corps du courriel aux utilisateurs EchapBox

> Objet : Information importante concernant votre compte EchapBox et vos données personnelles

---

Madame, Monsieur,

Nous vous contactons au sujet d'une évolution importante concernant la gestion de vos données personnelles sur la plateforme EchapBox.

**Fusion de nos bases de données**

Dans le cadre de l'amélioration de nos services, nous procédons à la fusion des bases de données de nos deux plateformes : EchapBox et Désir d'Ailleurs. Cette opération est réalisée dans un but de simplification administrative et de meilleure sécurisation de vos données. Vos droits ne sont pas modifiés par cette opération.

Conformément au Règlement Général sur la Protection des Données (RGPD), nous vous informons que vous disposez toujours des droits suivants sur vos données personnelles : droit d'accès, droit de rectification, droit à l'effacement, droit à la portabilité et droit d'opposition. Pour exercer ces droits, contactez-nous à l'adresse : contact@yak-a-partir.com

**Votre consentement pour le démarchage commercial**

Nous souhaiterions également pouvoir vous adresser des offres commerciales et promotionnelles de la part de Yak-à-Partir. Pour cela, nous avons besoin de votre consentement explicite.

Si vous souhaitez recevoir nos offres commerciales, nous vous invitons à donner votre accord en cliquant sur le lien suivant dans un délai d'**un mois** à compter de la réception de ce courriel :

👉 https://www.EchapBox.com/accordPubli

**Si vous ne souhaitez pas recevoir nos offres commerciales, vous n'avez rien à faire.** En l'absence de réponse dans ce délai, aucun démarchage commercial ne vous sera adressé.

Ce consentement est libre, éclairé et révocable à tout moment sur simple demande.

Nous restons à votre disposition pour toute question.

Cordialement,

L'équipe Yak-à-Partir

---

### Question B1.4 – Conservation de la trace du consentement et garantie de son intégrité

**Solution proposée :**

Pour documenter le processus de recueil du consentement et en garantir l'intégrité, on propose la solution suivante :

**1. Enregistrement de la trace en base de données**

Créer une table dédiée `ConsentementPubli` qui enregistre, pour chaque action de consentement :
- l'identifiant du client concerné,
- la date et l'heure exacte de l'action,
- la valeur de l'accord (true/false),
- l'adresse IP du client au moment de l'action,
- la version du texte d'information présentée.

Exemple :
```
ConsentementPubli(id, idClient, dateHeure, accord, adresseIP, versionTexte)
```

**2. Garantir l'intégrité de la trace**

Pour s'assurer que les enregistrements ne peuvent pas être modifiés ou supprimés après coup :
- **Droits en base de données** : le compte applicatif Web ne dispose que du droit `INSERT` sur cette table (pas d'`UPDATE` ni de `DELETE`).
- **Hachage** : calculer une empreinte cryptographique (hash SHA-256) de chaque enregistrement lors de sa création et la stocker. Toute modification ultérieure invaliderait le hash.
- **Journalisation externe** : exporter les enregistrements dans un journal d'audit sécurisé (fichier signé, stockage immuable, ou tiers de confiance).

---

### Question B1.5 – Structure de la table `ClientAnonyme`

Pour les statistiques par genre, tranche d'âge et département d'origine, les données nécessaires sont : civilité (pour le genre), date de naissance (pour la tranche d'âge), code postal (pour le département). Toutes les autres données personnelles doivent être supprimées (principe de minimisation des données du RGPD).

```
ClientAnonyme(id, civilité, anneeNaiss, departement)
Clé primaire : id
```

> - `civilité` remplace le genre (M./Mme).
> - `anneeNaiss` (année extraite de `dateNaiss`) suffit pour calculer une tranche d'âge ; la date complète n'est pas nécessaire.
> - `departement` (2 premiers chiffres du `codePostal`) suffit pour la statistique géographique ; l'adresse complète n'est pas nécessaire.

---

### Question B2.1 – Justification du niveau de gravité des risques R1 et R2

D'après la matrice EBIOS (Document B5), R1 et R2 sont placés en **gravité 4 / vraisemblance 4**, soit un **risque élevé, inacceptable**.

**Risque R1 – Acompte ≥ montant à payer :**

Un contrat avec un acompte supérieur ou égal au montant total signifie que **l'agence aurait encaissé un acompte couvrant la totalité ou plus de la prestation**, mais devrait rembourser la différence ou ne réaliserait aucun bénéfice. En cas d'exploitation malveillante (par ex. un employé interne ou un attaquant externe via injection SQL), cela pourrait générer des **pertes financières directes significatives** pour l'entreprise. La facture finale serait nulle ou négative, causant un préjudice comptable grave. La gravité 4 est donc justifiée par l'impact financier majeur.

**Risque R2 – Montant à payer < 75 € par personne/jour :**

L'agence facture un minimum de 75 € par participant par jour pour couvrir ses coûts (personnel, réseau de prestataires, marge). Un contrat en dessous de ce seuil générerait une **prestation à perte**. Si plusieurs contrats frauduleux sont créés à des tarifs inférieurs, l'impact financier cumulé peut être très important. De plus, cela affecterait la **viabilité économique** de l'entreprise à terme. La gravité 4 est justifiée.

---

### Question B2.2 – Requête pour détecter les contrats avec acompte ≥ montant à payer

En s'appuyant sur le schéma relationnel (Document B1) :

```sql
SELECT c.idCli, cl.nom, cl.prenom
FROM Client cl
JOIN Devis_Voyage dv ON cl.idCli = dv.idCli
JOIN Contrat_Voyage cv ON dv.idDevis = cv.idDevis
WHERE cv.acompte >= cv.montantAPayer;
```

---

### Question B2.3 – Complétion du déclencheur `before_insert_contrat_voyage`

Il faut vérifier que `montantAPayer >= 75 * nbParticipants * nbJours`. En s'appuyant sur la structure du trigger existant (Document B6) :

```sql
SET @nb_participants = NEW.nbParticipants;
SET @montant_minimum = 75 * @nb_jours * @nb_participants;

IF NEW.montantAPayer < @montant_minimum THEN
    SIGNAL SQLSTATE '10002'
    SET MESSAGE_TEXT = 'Le montant à payer est inférieur au montant minimum autorisé (75€ par participant et par jour)';
END IF;
```

**Trigger complet (partie complétée) :**

```sql
DELIMITER |
CREATE TRIGGER before_insert_contrat_voyage BEFORE INSERT
ON Contrat_Voyage FOR EACH ROW
BEGIN
    SET @nb_jours = (SELECT nbJours FROM Devis_Voyage WHERE idDevis = NEW.idDevis);

    IF @nb_jours < 3 THEN
        SIGNAL SQLSTATE '10001'
        SET MESSAGE_TEXT = 'Le devis validé par le contrat est d\'une durée inférieure à la durée minimale autorisée';
    END IF;

    -- Vérification du montant minimum (75€ par participant et par jour)
    SET @nb_participants = (SELECT nbParticipants FROM Devis_Voyage WHERE idDevis = NEW.idDevis);
    SET @montant_minimum = 75 * @nb_jours * @nb_participants;

    IF NEW.montantAPayer < @montant_minimum THEN
        SIGNAL SQLSTATE '10002'
        SET MESSAGE_TEXT = 'Le montant à payer est inférieur au montant minimum autorisé (75€ par participant et par jour)';
    END IF;

END |
```

> Note : `nbParticipants` se trouve dans `Devis_Voyage` d'après le schéma (Document B1). `NEW.nbParticipants` pourrait aussi être utilisé s'il figure directement dans `Contrat_Voyage` selon le schéma réel.

---

## DOSSIER C – Amélioration de la sécurité des applications Web

---

### Question C1.1 – Fonctionnement de la protection CSRF mise en place

En analysant le Document C3 (code source PHP) :

**Mécanisme utilisé : Synchronizer Token Pattern (jeton de synchronisation)**

Le fonctionnement est le suivant :

1. **Génération du jeton** : lors du chargement de la page `modifMdp.php`, le serveur récupère le jeton CSRF stocké en **variable de session** (`$_SESSION['token']`).

2. **Envoi au client** : ce jeton est intégré dans le formulaire HTML sous la forme d'un **champ caché** (`<input type="hidden" name="token" value="...">`). Il est donc transmis au navigateur de l'utilisateur.

3. **Soumission du formulaire** : lorsque l'utilisateur soumet le formulaire, le jeton du champ caché est envoyé au serveur dans les données POST (`$_POST['token']`).

4. **Vérification côté serveur** : dans `traitement.php`, le serveur compare le jeton reçu via POST (`$_POST['token']`) avec celui stocké en session (`$_SESSION['token']`). Si les deux jetons sont **identiques et non vides**, le traitement s'effectue. Sinon, une erreur est retournée.

**Pourquoi cela protège contre CSRF** : un attaquant peut forger une requête HTTP vers le serveur, mais il ne peut pas connaître la valeur du jeton stocké en session (inaccessible depuis un site tiers). La requête forgée ne contiendra pas le bon jeton et sera donc rejetée.

---

### Question C2.1 – Analyse du fichier de journalisation

#### a) Identification des événements

En analysant le Document C1 :

| Heure | Niveau | Événement |
|---|---|---|
| 21:41:18 | NOTICE | L'utilisateur **AllanG** a échoué à se connecter (une fois) |
| 21:41:20 | WARNING | Tentative de connexion avec des **champs vides** (utilisateur non identifié) |
| 21:41:24 | NOTICE | L'utilisateur **RichardP** a échoué à se connecter **5 fois consécutives** en moins d'une seconde |
| 21:41:26 | NOTICE | L'utilisateur **AllanG** s'est **connecté avec succès** |
| 21:41:26 | NOTICE | L'utilisateur **RichardP** a encore échoué à se connecter **3 fois supplémentaires** |

#### b) Hypothèse sur l'événement anormal – Note à destination du responsable

---

**NOTE INTERNE**
**Destinataire :** Responsable sécurité
**Objet :** Anomalie détectée dans les journaux de l'application Désir d'Ailleurs – 10/05/2023

À 21h41, l'analyse des journaux révèle que l'utilisateur **RichardP** a subi **8 tentatives de connexion en échec** en l'espace de 2 secondes (de 21:41:24 à 21:41:26). La fréquence de ces tentatives (plusieurs à la même seconde) est incompatible avec une saisie humaine manuelle.

**Hypothèse :** Il s'agit vraisemblablement d'une **attaque par force brute** ou par **dictionnaire** automatisée, visant à deviner le mot de passe du compte de RichardP. L'attaquant utilise un outil automatisé qui génère et teste des combinaisons de mots de passe à très haute fréquence.

**Recommandations :**
- Bloquer temporairement le compte de RichardP dans l'attente d'une vérification.
- Mettre en place un mécanisme de **verrouillage de compte** après N tentatives échouées consécutives.
- Envisager l'ajout d'un **CAPTCHA** ou d'un délai progressif entre les tentatives.
- Contacter RichardP pour l'informer et vérifier s'il est à l'origine de ces tentatives.

---

### Question C2.2 – Évolution de la base de données pour référencer les tentatives de connexion

#### a) Structure proposée

Il faut créer une nouvelle table `TentativeConnexion` liée à la table `Client`. Chaque tentative est associée à un seul utilisateur et possède un résultat (réussite ou échec).

```
TentativeConnexion(idTentative, dateHeure, resultat, idCli)
  Clé primaire : idTentative
  Clé étrangère : idCli en référence à idCli de Client
```

- `idTentative` : identifiant auto-incrémenté de la tentative.
- `dateHeure` : horodatage de la tentative (type DATETIME).
- `resultat` : booléen ou ENUM('succes', 'echec') indiquant le résultat.
- `idCli` : référence à l'utilisateur concerné.

#### b) Deux enregistrements illustrant des tentatives par un même utilisateur

| idTentative | dateHeure | resultat | idCli |
|---|---|---|---|
| 1 | 2023-05-10 21:41:24 | echec | 42 |
| 2 | 2023-05-10 21:41:26 | echec | 42 |

> Ces deux enregistrements représentent deux tentatives échouées de connexion par l'utilisateur d'identifiant 42 (correspondant à RichardP), illustrant le cas observé dans le fichier de journalisation.

---

### Question C2.3 – Solution pour désactiver un compte compromis

**Solution proposée : ajout d'un champ `estActif` dans la table `Client` couplé à un déclencheur de surveillance**

**Description :**

1. **Modification de la table `Client`** : ajouter un champ booléen `estActif` (valeur par défaut : `TRUE`) permettant d'indiquer si le compte est actif ou désactivé.

2. **Déclencheur automatique** : créer un déclencheur `AFTER INSERT` sur la table `TentativeConnexion` qui, après chaque insertion d'une nouvelle tentative en échec, compte le nombre de tentatives échouées récentes pour cet utilisateur (par exemple sur les 5 dernières minutes). Si ce nombre dépasse un seuil défini (par exemple 5 échecs), le déclencheur met automatiquement `estActif = FALSE` pour le compte concerné dans la table `Client`.

3. **Contrôle à l'authentification** : lors de chaque tentative de connexion, l'application vérifie la valeur de `estActif` avant de valider l'authentification. Si le compte est désactivé, la connexion est refusée avec un message approprié.

4. **Réactivation** : l'administrateur peut consulter les comptes désactivés via une interface dédiée, mener ses vérifications, puis réactiver le compte en remettant `estActif = TRUE` si nécessaire.

Cette solution est entièrement **automatique**, **traçable** (via la table `TentativeConnexion`), et laisse à l'administrateur le **contrôle de la réactivation**.

---

*Correction réalisée sur la base du sujet BTS SIO SLAM – U6 Cybersécurité – Session 2023 Nouvelle-Calédonie (Code sujet : 23SI6SLAM-NC1)*
