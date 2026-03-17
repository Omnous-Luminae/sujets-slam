# Correction – BTS SIO SLAM · U7 Cybersécurité · Session 2025
> Sujet : Puces'In · Code : 25SI7SLAM-NC1

---

## DOSSIER A – Sécurisation des applications VerifColis et Puces'In Rachète

---

### Mission A1 – Sécurisation de l'application client lourd VerifColis

#### Question A.1.1 – Conséquence principale de la malveillance

Un employé a saisi un prix de rachat proposé supérieur au prix de revente du livre, ce qui signifie que **Puces'In rachète un livre plus cher qu'elle ne peut le revendre**. La conséquence directe est une **perte financière** pour l'entreprise : la marge sur ce livre est négative, voire la transaction génère un déficit (le prix de rachat dépasse le prix de revente).

---

#### Question A.1.2 – Modifications à apporter à la méthode `traiterUnLivre`

Pour intégrer la règle « *le prix de rachat proposé ne peut pas dépasser 10 % du prix de revente du livre en état acceptable* », les modifications suivantes sont nécessaires :

1. **Récupérer le prix de revente** du livre pour la publication concernée et pour l'état « acceptable » (id = 4) depuis la table `Revendre`, en utilisant `idPublication` et `idEtatLivre = 4`.
2. **Calculer le seuil maximum autorisé** : `prixMaxAutorise = prixRevente * 0.10`.
3. **Ajouter un test conditionnel** : si `prixRachatPropose > prixMaxAutorise`, alors ne pas exécuter la requête `UPDATE` (et signaler l'erreur à l'employé via l'interface, par exemple une alerte).
4. **Exécuter la requête SQL** uniquement si le prix proposé est inférieur ou égal au seuil calculé.

> **Remarque** : la règle s'applique uniquement lorsque l'état du livre est « acceptable » (id = 4), donc ce contrôle s'insère dans le bloc `if (unLivre.getLeEtatLivre().getId() == 4)` existant.

---

### Mission A2 – Sécurisation de l'application mobile Puces'In Rachète

#### Question A.2.1 – Deux conséquences de la malveillance

1. **Perte financière liée aux frais de port** : Puces'In prend en charge les frais d'expédition dès que le colis est déposé (étape 7 du processus). Les concurrents obtiennent des bordereaux gratuits pour expédier leurs propres colis, aux frais de Puces'In.

2. **Saturation des ressources du centre de tri** : la réception de nombreux colis vides mobilise le temps des employés chargés de vérifier le contenu des colis (utilisation de VerifColis), et génère un traitement inutile qui nuit à la productivité et à la qualité de service.

---

#### Question A.2.2 – Complétion de la méthode `validerColis`

```java
public Boolean validerColis(Colis leColis) {
    int idVendeur = leColis.getLeVendeur().getId(); // récupération de l'identifiant du vendeur

    // Récupération du nombre de bordereaux générés ce mois-ci pour ce vendeur
    int nbBordereaux = VendeurDAO.getNbBordereauDuMois(idVendeur);

    // Vérification de la limite de 4 bordereaux par mois
    if (nbBordereaux >= 4) {
        return false; // limite atteinte, on refuse la génération
    }

    genererPdfBordereau(leColis);               // génération du PDF
    ColisDAO.enregistrerColisAvecLivres(leColis); // enregistrement en base
    return true;
}
```

---

### Mission A3 – Gestion de l'API REST

#### Question A.3.1 – Identification des deux tests vulnérables

**Test n°1** et **Test n°2** présentent des vulnérabilités.

**a) Tests concernés :**
- **Test n°1** : `GET api.pucesin.com/livres` sans aucune authentification
- **Test n°2** : `GET api.pucesin.com/colis` sans aucune authentification

**b) Vulnérabilités mises en évidence :**

- **Test n°1** : L'API retourne la liste de tous les livres sans exiger d'authentification. N'importe quel utilisateur anonyme peut accéder à ces données. Il n'y a aucun contrôle d'accès.

- **Test n°2** : L'API retourne les données personnelles de **tous les utilisateurs** (nom, prénom, ville, adresse e-mail) sans authentification. Un attaquant peut ainsi récupérer massivement des données personnelles de tous les clients.

**c) Critères de sécurité concernés :**

| Test | Critère |
|------|---------|
| Test n°1 | **Confidentialité** (données du catalogue exposées sans contrôle) |
| Test n°2 | **Confidentialité** (données personnelles de tous les utilisateurs accessibles librement) |

> **Test n°4** (10 000 requêtes → erreur 500) concerne la **disponibilité** (attaque de type DoS), mais n'est pas classé parmi les deux principaux puisqu'il ne s'agit pas d'une faille d'accès aux données mais d'une absence de limitation de débit.

---

#### Question A.3.2 – La méthode `authentifierUtilisateur` est-elle sécurisée ?

**Oui, la méthode est sécurisée**, pour les raisons suivantes :

- Elle utilise une **requête préparée** (`PreparedStatement`) avec des paramètres (`?`) : cela empêche les injections SQL, car les valeurs saisies par l'utilisateur ne sont jamais concaténées directement dans la requête.
- Le mot de passe est **haché** avant d'être comparé en base (`hashpassword(mdp)`), ce qui signifie qu'il n'est pas stocké en clair.

---

#### Question A.3.3 – Solution technique pour limiter le nombre de requêtes

La solution technique à mettre en place est le **rate limiting** (limitation du débit de requêtes), aussi appelé **throttling**.

Concrètement, on peut utiliser :
- Un **pare-feu applicatif (WAF)** ou un **reverse proxy** (comme Nginx ou Traefik) configuré pour limiter le nombre de requêtes par IP et par unité de temps.
- Un **IPS (Intrusion Prevention System)** déjà mentionné, qui peut détecter et bloquer automatiquement les sources générant un volume anormal de requêtes.
- Un mécanisme de **quota par jeton JWT** (une fois les JWT intégrés) : comptabiliser les requêtes associées à un utilisateur et renvoyer un code HTTP `429 Too Many Requests` lorsque le seuil est dépassé.

---

#### Question A.3.4 – Intégrité garantie par HMAC dans la signature JWT

La signature d'un jeton JWT est calculée ainsi :

```
Signature = HMACSHA256(base64(header) + "." + base64(payload), clé_secrète)
```

La **clé secrète** n'est connue que du serveur. Si un attaquant modifie n'importe quel octet du header ou du payload (par exemple pour changer la date d'expiration ou l'identifiant utilisateur), il devrait **recalculer la signature**, ce qui est impossible sans connaître la clé secrète.

Ainsi, lorsque le serveur reçoit un jeton, il recalcule la signature à partir du header et du payload reçus, et compare avec la signature fournie. Toute divergence révèle une **altération du jeton**, qui est alors rejeté. C'est ce mécanisme qui **garantit l'intégrité** du token.

---

#### Question A.3.5 – Pourquoi HTTPS est nécessaire malgré l'authentification par JWT

Le JWT garantit l'**intégrité** et l'**authenticité** du jeton, mais **pas la confidentialité des échanges**.

Sans HTTPS, les communications transitent en clair sur le réseau. Un attaquant pratiquant une **écoute passive (sniffing)** peut intercepter le jeton JWT lors d'une requête et **l'utiliser lui-même** (attaque par rejeu, ou *token hijacking*). Il peut ainsi se faire passer pour l'utilisateur légitime auprès de l'API.

HTTPS chiffre l'intégralité du trafic HTTP (y compris les en-têtes contenant le jeton), rendant son interception inutilisable.

---

#### Question A.3.6 – Cause de l'échec du test n°2

Le test n°2 est réalisé le **02/05/2024 à 10h30:00**, en réutilisant le jeton obtenu lors du test n°1 effectué à **10h08:20**.

En décodant le payload du jeton du test n°1 :
- `iat` = `1714637302` → correspond à **02/05/2024 à 10:08:22**
- `exp` = `1714637902` → correspond à **02/05/2024 à 10:18:22**

La **durée de validité du jeton est de 600 secondes (10 minutes)**.

Or, le test n°2 est lancé à 10h30:00, soit **21 minutes et 38 secondes** après la génération du jeton, qui a donc **expiré depuis plus de 11 minutes**.

**Conclusion** : l'erreur `ExpiredJwtException` est retournée car le jeton JWT utilisé a dépassé sa date d'expiration (`exp`). Il aurait fallu regénérer un nouveau jeton via `/auth` avant de relancer la requête.

---

## DOSSIER B – Gestion des droits sur les données à caractère personnel

---

### Mission B1 – Contrôle du respect des obligations légales

#### Question B.1.1

**a) Deux droits manquants dans la liste (articles 15-22 du RGPD) :**

- **Droit de rectification** (article 16) : toute personne peut demander la correction de données inexactes la concernant.
- **Droit à l'effacement** (article 17), aussi appelé « droit à l'oubli » : toute personne peut demander la suppression de ses données personnelles.

> *Autres droits possibles selon la liste fournie : droit à la limitation du traitement (déjà cité), droit à la portabilité (déjà cité), droit d'opposition (déjà cité). Les droits non listés incluent aussi le droit de ne pas faire l'objet d'une décision automatisée (article 22).*

**b) Délai réglementaire de réponse :**

Le RGPD (article 12) impose de répondre aux demandes d'exercice des droits **dans un délai d'un mois** à compter de la réception de la demande. Ce délai peut être prolongé de deux mois supplémentaires en cas de complexité, mais le demandeur doit en être informé dans le premier mois.

---

#### Question B.1.2 – Conservation des fichiers d'identité depuis 2018 : est-ce réglementaire ?

**Non, ce choix n'est pas réglementaire.**

Le RGPD impose le **principe de minimisation des données** et de **limitation de la conservation** : les données à caractère personnel ne doivent pas être conservées au-delà de ce qui est strictement nécessaire à la finalité pour laquelle elles ont été collectées.

Les documents d'identité (passeports, cartes d'identité) sont collectés uniquement pour vérifier l'identité du demandeur **au moment du traitement de la demande**. Une fois la demande traitée, ces fichiers **n'ont plus de raison d'être conservés**. Les garder indéfiniment depuis 2018 constitue une violation des principes de minimisation et de durée de conservation définis par le RGPD.

---

#### Question B.1.3 – Document requis par le RGPD

Le traitement de saisie des demandes d'exercice de droits doit être décrit dans le **Registre des activités de traitement** (RAT), aussi appelé « registre des traitements ».

Ce document, rendu obligatoire par l'article 30 du RGPD pour les organismes traitant des données personnelles, recense tous les traitements effectués, leurs finalités, les catégories de données concernées, les durées de conservation et les mesures de sécurité associées.

---

### Mission B2 – Conception de la base de données

#### Question B.2.1 – Adaptation du schéma entité-association

**Schéma de départ (Document B1) :**

- `EtatDemande` (id, libelle) — reliée à `Demande` par « être dans un état » (0,n côté EtatDemande / 1,1 côté Demande) : seul l'état courant est conservé.
- `Demande` (id, nomDemandeur, prenomDemandeur, melDemandeur, nomFichierPieceIdentite) — reliée à `Droit` par « concerner » (1,1 côté Demande / 0,n côté Droit).
- `Droit` (id, libelle)

---

**Modifications à apporter :**

**1. Garantir la gestion du délai réglementaire**
Ajouter deux attributs dans l'entité **`Demande`** :
- `dateSaisie` — date d'enregistrement de la demande (point de départ du délai d'un mois)
- `dateTraitement` — date de clôture de la demande (permet aussi de calculer la durée de traitement)

**2. Statistiques sur la durée de traitement par type de droit**
Les attributs `dateSaisie` et `dateTraitement` ajoutés dans `Demande`, combinés à la relation existante avec `Droit`, suffisent. Aucune entité supplémentaire n'est nécessaire pour ce point.

**3. Conservation des dates de changement d'état**
La relation actuelle « être dans un état » ne conserve que l'état courant. Il faut la transformer en **entité-association `ChangerEtat`** (ou association portant un attribut) pour mémoriser chaque transition :

- Attribut ajouté à la relation : `dateChangement`
- Cardinalités : `EtatDemande` (0,n) — `changerEtat` — (1,n) `Demande`
  *(une demande a connu au moins un état, un état peut avoir été attribué à plusieurs demandes)*

**4. Conservation des échanges**
Ajouter une nouvelle entité **`Echange`** reliée à `Demande` par une association « avoir » :

Attributs de `Echange` :
- `id` (identifiant)
- `dateEchange`
- `description`
- `codeOrigine` — `'D'` pour le demandeur, `'P'` pour le DPO de Puces'In

Cardinalités : `Demande` (1,1) — `avoir` — (0,n) `Echange`
*(un échange est lié à exactement une demande ; une demande peut avoir zéro ou plusieurs échanges)*

---

**Schéma entité-association final :**

```
┌───────────────┐  0,n   ┌─────────────────┐  1,n  ┌──────────────────────────────────────┐
│ EtatDemande   │────────│  changerEtat    │───────│ Demande                              │
│───────────────│        │─────────────────│       │──────────────────────────────────────│
│ id            │        │ dateChangement  │       │ id                                   │
│ libelle       │        └─────────────────┘       │ nomDemandeur                         │
└───────────────┘                                  │ prenomDemandeur                      │
                                                   │ melDemandeur                         │
                                                   │ nomFichierPieceIdentite              │
                                                   │ dateSaisie        ← AJOUT            │
                                                   │ dateTraitement    ← AJOUT            │
                                                   └──────────┬──────────────┬────────────┘
                                                              │ 1,1          │ 1,1
                                                        [concerner]      [avoir]
                                                              │ 0,n          │ 0,n
                                                   ┌──────────┘    ┌─────────────────────┐
                                                   │ Droit         │ Echange  ← AJOUT    │
                                                   │───────────    │─────────────────────│
                                                   │ id            │ id                  │
                                                   │ libelle       │ dateEchange         │
                                                   └───────────    │ description         │
                                                                   │ codeOrigine         │
                                                                   └─────────────────────┘
```

---

**Récapitulatif des 4 ajouts :**

| Besoin | Modification apportée |
|--------|----------------------|
| Gestion du délai réglementaire | `dateSaisie` + `dateTraitement` dans `Demande` |
| Statistiques par type de droit | Couvert par les attributs ci-dessus + relation `Droit` existante |
| Historique des changements d'état | Relation « être dans un état » → entité-association `changerEtat` avec attribut `dateChangement` |
| Conservation des échanges | Nouvelle entité `Echange` (id, dateEchange, description, codeOrigine) liée à `Demande` |

---

## DOSSIER C – Résolution d'incidents sur le site web pucesin.com

---

### Mission C1 – Identification d'attaques et contre-mesures

#### Question C.1.1 – Ticket S-C-1092

**a) Technique utilisée par l'attaquant :**
**Le phishing** (hameçonnage) : l'attaquant envoie un message frauduleux (e-mail ou autre) imitant une entité de confiance pour tromper l'employé.

**b) Attaque dont l'employé a été victime :**
**Le spear phishing** (hameçonnage ciblé) : une variante personnalisée du phishing ciblant spécifiquement un individu ou une organisation, rendant le message plus crédible.

> *Selon les informations du ticket, si l'employé a cliqué sur un lien malveillant conduisant à une fausse page de connexion, on peut également caractériser cela comme une attaque de type **vol de session** ou **credential harvesting**.*

---

#### Question C.1.2 – Deux moyens de sensibiliser les employés

1. **Organiser des sessions de formation et de sensibilisation** à la cybersécurité, incluant des exemples concrets de phishing, avec des explications sur comment identifier un e-mail frauduleux (vérification de l'expéditeur, liens suspects, fautes d'orthographe, demandes inhabituelles).

2. **Réaliser des campagnes de phishing simulé** (tests de phishing internes) : envoyer de faux e-mails de phishing aux employés, mesurer le taux de clics, puis informer et former ceux qui ont été « piégés » pour renforcer leur vigilance de manière pratique.

---

#### Question C.1.3 – Ticket S-A-0095 : deux contre-mesures

D'après le ticket S-A-0095 (incident lié à l'expiration du nom de domaine pucesin.com), Puces'In aurait dû :

1. **Mettre en place un système d'alerte automatique** sur la date d'expiration du nom de domaine (par exemple, avec le programme décrit en Document C3), pour être prévenu plusieurs mois à l'avance et procéder au renouvellement en temps utile.

2. **Activer le renouvellement automatique** du nom de domaine auprès du bureau d'enregistrement (registrar), afin que le domaine soit renouvelé sans intervention manuelle, éliminant ainsi le risque d'oubli.

---

#### Question C.1.4 – Complétion du programme PHP (rappel à 1 semaine)

```php
// renseigne le nom de domaine
$domain = 'pucesin.com';
// exécution de la commande whois pour obtenir les informations du nom de domaine
$info_nom_domaine = shell_exec('whois ' . escapeshellarg($domain));
// Récupération de la date d'expiration du nom de domaine
preg_match('/Expiry Date:(.*?)\n/', $info_nom_domaine, $matches);
$date_expiration_complete = trim($matches[1]);
$date_expiration = date('Y-m-d', strtotime($date_expiration_complete));
// Récupération de la date du jour
$date_jour = date('Y-m-d');
// contrôle de la date d'expiration
$date_dans_3_mois = date('Y-m-d', strtotime('+3 month', strtotime($date_jour)));
if ($date_expiration == $date_dans_3_mois) {
    $message = "Le nom de domaine " . $domain . " expirera dans 3 mois";
} else {
    $date_dans_1_mois = date('Y-m-d', strtotime('+1 month', strtotime($date_jour)));
    if ($date_expiration == $date_dans_1_mois) {
        $message = "Le nom de domaine " . $domain . " expirera dans 1 mois";
    } else {
        // Ajout du rappel à 1 semaine
        $date_dans_1_semaine = date('Y-m-d', strtotime('+7 days', strtotime($date_jour)));
        if ($date_expiration == $date_dans_1_semaine) {
            $message = "Le nom de domaine " . $domain . " expirera dans 1 semaine";
        }
    }
}
if (isset($message)) {
    envoyer_mail("admin@pucesin.com", "Nom de domaine " . $domain, $message);
}
```

> **Explication** : on ajoute un bloc `else` imbriqué après le test à 1 mois. On calcule `$date_dans_1_semaine` en ajoutant `'+7 days'` à la date du jour (la remarque du sujet indique que la syntaxe `'- 2 days'` est utilisée, donc `'+7 days'` est correct). Si la date d'expiration correspond à cette date, on prépare le message d'alerte à 1 semaine.

---

### Mission C2 – Analyse de traces (logs)

#### Question C.2.1 – Type d'attaque subi (Document C4 – auth.log)

À la lecture des traces, on observe de nombreuses tentatives de connexion échouées consécutives sur le compte `admsys` depuis la même adresse IP (`51.87.35.150`), suivies d'une connexion réussie.

Il s'agit d'une **attaque par force brute** (brute force attack) : l'attaquant essaie de manière systématique des mots de passe jusqu'à trouver le bon.

---

#### Question C.2.2 – Deux raisons possibles du succès de l'attaque

1. **Mot de passe trop faible** : le compte `admsys` avait probablement un mot de passe peu complexe (court, sans caractères spéciaux, ou présent dans un dictionnaire courant), permettant à l'attaquant de le trouver rapidement.

2. **Absence de mécanisme de blocage après plusieurs tentatives échouées** : aucune politique de verrouillage de compte (account lockout) ou de blocage d'IP n'était en place, permettant à l'attaquant d'effectuer autant de tentatives qu'il le souhaitait sans être bloqué.

---

#### Question C.2.3 – Risques par principe de sécurité informatique

| Principe | Risque lié à l'attaque |
|----------|----------------------|
| **Confidentialité** | L'attaquant a obtenu l'accès au compte `admsys` (droits maximum) : il peut lire toutes les données sensibles (données personnelles clients, données bancaires, informations commerciales). |
| **Intégrité** | Ayant tous les droits, l'attaquant peut modifier, falsifier ou supprimer des données en base (ex : manipulation des montants de ventes, d'où les anomalies constatées par la comptabilité). |
| **Disponibilité** | L'attaquant peut rendre le service indisponible (suppression de données, corruption de la base, arrêt du serveur). |

---

#### Question C.2.4 – Fuite de données (Document C5 – audit MySQL)

**a) Acteurs à informer :**

- La **CNIL** (Commission Nationale de l'Informatique et des Libertés), autorité de contrôle française, dans un délai de 72 heures après la découverte de la violation (article 33 du RGPD).
- Les **personnes concernées** (clients, vendeurs, acheteurs dont les données ont été compromises), si la violation est susceptible d'engendrer un risque élevé pour leurs droits et libertés (article 34 du RGPD).
- La **direction de Puces'In** et le **DPO** (Délégué à la Protection des Données) de l'entreprise.

**b) Document où la fuite doit être consignée :**

La fuite de données doit être consignée dans le **registre des violations de données** (ou registre des incidents de sécurité), document interne obligatoire imposé par l'article 33§5 du RGPD, qui recense toutes les violations de données à caractère personnel.

**c) Deux actions pour garantir l'intégrité des preuves :**

1. **Sauvegarder et archiver les fichiers de logs** (auth.log, audit MySQL, etc.) sur un support séparé et sécurisé, sans les modifier, afin de préserver leur intégrité en tant que preuves numériques.
2. **Calculer une empreinte cryptographique (hash)** des fichiers de logs (par exemple avec SHA-256) et la conserver, permettant ainsi de prouver à tout moment que les fichiers n'ont pas été altérés après leur collecte.

---

#### Question C.2.5 – Requête pour supprimer les privilèges abusifs

D'après le Document C5, les requêtes malveillantes ont créé un utilisateur `lecteur` connecté depuis `dwln-app.to` et lui ont accordé tous les droits (`GRANT ALL ON *.*`).

```sql
REVOKE ALL PRIVILEGES ON *.* FROM 'lecteur'@'dwln-app.to';
```

> On peut également supprimer entièrement le compte avec :
> ```sql
> DROP USER 'lecteur'@'dwln-app.to';
> ```
> Ce qui révoque implicitement tous ses privilèges et supprime le compte.

---

### Mission C3 – Sécurisation des accès à une base de données

#### Question C.3.1

**a) Requêtes de création du compte `statistiques`**

D'après le schéma relationnel (Document commun 2), les tables utiles aux statistiques sont :
- `CommandeInternet` (livres commandés)
- `PublicationLivre` (date de publication, prix de vente neuf)
- `TypePublication` (libellés des types de publication)
- `Livre` (lien entre commande et publication)

```sql
-- Création du compte utilisateur statistiques accessible uniquement depuis 95.10.2.54
CREATE USER 'statistiques'@'95.10.2.54' IDENTIFIED BY 'motDePasseSecurise';

-- Attribution des droits de lecture uniquement sur les tables nécessaires
GRANT SELECT ON pucesin.CommandeInternet TO 'statistiques'@'95.10.2.54';
GRANT SELECT ON pucesin.PublicationLivre TO 'statistiques'@'95.10.2.54';
GRANT SELECT ON pucesin.TypePublication TO 'statistiques'@'95.10.2.54';
GRANT SELECT ON pucesin.Livre TO 'statistiques'@'95.10.2.54';
```

> Seul le privilège `SELECT` est accordé (lecture seule), conformément au principe du moindre privilège.

**b) Solution technique alternative sans mise en œuvre**

Une solution différente serait de créer une **vue SQL** (`VIEW`) regroupant uniquement les colonnes nécessaires aux statistiques (livres commandés, date de publication, prix de vente neuf, libellé du type de publication), et d'accorder au compte `statistiques` un droit `SELECT` **uniquement sur cette vue**, sans aucun accès direct aux tables sous-jacentes.

Cela permet de restreindre encore davantage l'accès aux données : l'utilisateur ne voit que les colonnes exposées par la vue, et non l'ensemble des colonnes des tables (qui peuvent contenir des données sensibles comme les IBAN ou les mots de passe).

---

*Fin de correction – BTS SIO SLAM · U7 Cybersécurité · Session 2025*
