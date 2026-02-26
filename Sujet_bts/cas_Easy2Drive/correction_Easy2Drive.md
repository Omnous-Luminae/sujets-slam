# Correction rédigée – Cas Easy2Drive (BTS SIO SLAM U6 – Session 2022)

> Correction rédigée à partir de la copie du sujet fournie dans le chat. Certaines réponses (notamment celles liées à des documents graphiques non fournis : maquettes, schémas BD_RGPD_LOGS, diagrammes) sont proposées sous forme de solution cohérente et argumentée, conformément aux attendus U6.

---

## Dossier A – Sécurisation de l’application e-learning

### Mission A1 – Évaluation des risques à partir des user stories

#### A.1.1

**a) Disponibilité : différence entre les récits 1 et 2**

- **Récit 1 (famille consulte le site sans compte)** : l’indisponibilité est certes gênante (perte d’opportunités commerciales, image), mais elle ne bloque pas un processus métier critique et n’empêche pas un utilisateur authentifié de poursuivre une formation. Le besoin de disponibilité est donc **modéré**.
- **Récit 2 (élève modifie son mot de passe)** : l’action touche directement l’**accès au compte**. Si la fonction est indisponible au moment où l’élève doit sécuriser/recouvrer l’accès, cela peut mener à une **perte d’accès**, à un maintien d’un mot de passe faible/compromis, et à une augmentation du risque de compromission. La disponibilité a donc un niveau **important**.

**b) Intégrité et confidentialité du récit 2**

- **Intégrité importante** : la modification de mot de passe doit être exacte et non altérée (mot de passe réellement remplacé, respect des règles, absence de corruption). Une erreur d’intégrité peut provoquer un verrouillage, une usurpation ou une perte de contrôle du compte.
- **Confidentialité importante** : la donnée manipulée (secret d’authentification, ou son hash, ainsi que les indicateurs de politique) est hautement sensible. Toute divulgation (ex : mot de passe en clair, fuite de hash, fuite de règles internes favorisant une attaque) augmente fortement le risque de compromission.

**c) Preuve : différence entre les récits 1 et 3**

- **Récit 1** : consultation publique d’information ; la traçabilité opposable est généralement **sans objet** (pas de litige fort lié à un acte authentifié).
- **Récit 3 (élève poste un commentaire/avis)** : publication potentiellement litigieuse (diffamation, injure, contestation de modération, contestation d’attribution). Il est nécessaire de conserver des **preuves** : auteur, date/heure, contexte, et actions de modération, donc niveau **important**.

---

### Mission A2 – Prise en compte du RGPD

#### A.2.1 – Non-conformité cookies (septembre 2020)

Le bandeau actuel se limite à : « Nous utilisons des cookies pour nous assurer du bon fonctionnement… ».

Or, selon la délibération CNIL (17/09/2020) :
- l’utilisateur doit être **clairement informé des finalités** des cookies ;
- le **consentement implicite** n’est plus acceptable ;
- l’interface doit proposer un **choix clair** : **Accepter / Refuser / Gérer (paramétrer)**.

Ainsi, le bandeau ne permet pas un consentement libre, spécifique, éclairé et univoque, ni un refus aussi simple que l’acceptation.

#### A.2.2 – Données personnelles collectées (récit utilisateur 1)

D’après la politique (doc A3), lors d’une consultation à des fins d’information, sont collectées :
- **adresse IP** : donnée personnelle (identifie indirectement une personne / terminal) ;
- **type d’appareil**, **version navigateur**, **résolution écran**, **OS**, **langue** : données pouvant participer à une **empreinte** du terminal, donc potentiellement personnelles ;
- **teneur des requêtes** : peut révéler des informations sur l’utilisateur (centres d’intérêt) ;

=> Ce sont des **données à caractère personnel** car elles se rapportent à une personne identifiable directement ou indirectement (RGPD), notamment via l’IP et le profilage/empreinte.

---

### Mission A3 – Sécurité du mot de passe

#### A.3.1

**a) Pourquoi la communication et l’utilisation du mot de passe initial sont insuffisantes**

- Le mot de passe initial est **envoyé en clair par courriel** : le mail peut être intercepté/consulté (boîte mail compromise, transfert, accès familial, etc.).
- L’élève peut **conserver** ce mot de passe « tout au long de la formation » : un secret initial, souvent généré et transmis par un canal faible, ne doit pas rester valide durablement.
- Risque accru de **réutilisation**, de **devinabilité**, et d’attaque (phishing, compromission mail).

**b) Meilleure solution pour communiquer le mot de passe initial**

Ne pas transmettre de mot de passe permanent.

Solution recommandée :
- envoyer un **lien d’activation / de création de mot de passe** à usage unique, avec **jeton** aléatoire, **expiration courte** (ex : 24h), et invalidation après usage ;
- forcer la création d’un mot de passe conforme CNIL lors de la première connexion.

#### A.3.2 – Fonction verifPassword

Rappel (A5) :
- longueur >= 8 donne 1 point longueur ;
- complexité : minuscule +1, majuscule +2, chiffre +3 ;
- résultat = points_long * points_comp ;
- mot de passe valide si résultat == 6.

**a) Politique actuelle (longueur/complexité)**

Pour obtenir 6 :
- il faut **longueur >= 8** (points_long = 1), sinon résultat = 0.
- et **points_comp = 6**.

Or points_comp vaut 6 si et seulement si :
- présence d’au moins **1 minuscule** (1)
- présence d’au moins **1 majuscule** (2)
- présence d’au moins **1 chiffre** (3)

=> Politique actuelle : **au moins 8 caractères**, avec au minimum **1 minuscule, 1 majuscule, 1 chiffre**. Aucun caractère spécial n’est exigé.

**b) Modification pour respecter toutes les recommandations CNIL**

CNIL :
- longueur minimum **12** ;
- minuscule (1), majuscule (2), chiffre (3), spécial (4) ;
- seuil demandé dans l’énoncé : **>= 10**.

On remplace la logique “produit” par une logique “somme” (plus adaptée au barème CNIL) :
- points_long = 1 si longueur >= 12 (sinon 0)
- points_comp = somme des points des 4 classes
- total = points_long + points_comp
- valide si total >= 10

Extrait de code (uniquement parties modifiées/ajoutées) :

```php
function verifPassword($mdp): bool
{
    $longueur = strlen($mdp);
    $points_long = 0;
    $points_comp = 0;

    // longueur CNIL
    if ($longueur >= 12) { $points_long = 1; }

    // complexité CNIL
    if (preg_match("/[a-z]/", $mdp)) { $points_comp += 1; }
    if (preg_match("/[A-Z]/", $mdp)) { $points_comp += 2; }
    if (preg_match("/[0-9]/", $mdp)) { $points_comp += 3; }
    if (preg_match("/\\W/", $mdp)) { $points_comp += 4; }

    $points_total = $points_long + $points_comp;
    return ($points_total >= 10);
}
c) Modification / complétion des tests unitaires

Objectif : couvrir longueur, absence de catégories, et cas valide.

PHP
public function testVerifPassword()
{
    // trop court
    $this->assertSame(false, verifPassword("Qam3"));

    // >=12 mais manque un chiffre
    $this->assertSame(false, verifPassword("qamQdVDbdAbc"));

    // >=12 mais pas de majuscule
    $this->assertSame(false, verifPassword("qamqdvdbabc3"));

    // >=12 mais pas de minuscule
    $this->assertSame(false, verifPassword("QAMQDVDBABC3"));

    // >=12 avec min+maj+chiffre mais pas de spécial => total = 1 + (1+2+3)=7 < 10
    $this->assertSame(false, verifPassword("Qamqdvdbabc3"));

    // cas valide : >=12 + min+maj+chiffre+spécial => total = 1 + (1+2+3+4)=11
    $this->assertSame(true, verifPassword("Qamqdvdbabc3!"));
}
A.3.3 – Renouvellement MDP (base de données)
a) Requête ALTER TABLE

SQL
ALTER TABLE Utilisateur
ADD dateMajMDP DATE NOT NULL DEFAULT (CURRENT_DATE());
(NB : selon la version/configuration MySQL, l’expression DEFAULT (CURRENT_DATE()) peut être refusée. Une alternative acceptable dans le cadre du sujet est de mettre une valeur par défaut fixe (ex : DEFAULT '2022-01-01') puis d’initialiser dateMajMDP à la création du compte et à chaque changement de mot de passe (application / procédure / trigger). L’idée attendue : champ obligatoire non nul, initialisé lors de la création.)

b) Fonction stockée renouvelleMDP(idEleve)

Retourne vrai si le mot de passe n’a pas été changé depuis plus de 90 jours.

SQL
CREATE FUNCTION renouvelleMDP(numEleve INT)
RETURNS BOOLEAN
BEGIN
    DECLARE v_date DATE;
    DECLARE v_retour BOOLEAN DEFAULT FALSE;

    SELECT dateMajMDP INTO v_date
    FROM Utilisateur
    WHERE id = numEleve;

    IF (DATE_ADD(v_date, INTERVAL 90 DAY) < CURRENT_DATE()) THEN
        SET v_retour = TRUE;
    END IF;

    RETURN v_retour;
END;
Dossier B – Conclusions audit de sécurité
Mission B1 – Garantie Réussite
B.1.1 – Conséquence principale pour Easy2Drive
La conséquence majeure est financière et juridique :

Easy2Drive rembourse des frais à tort (perte financière) ;
risque de fraude massive, impact réputationnel, et litiges avec d’autres auto-écoles/clients.
B.1.2
a) Conditions mal ou non implémentées

En comparant doc B1 et trigger B2 :

“L’échec date de moins de 6 mois” : le trigger teste :
SQL
IF DATE_ADD(NEW.dateEtg, INTERVAL 6 MONTH) >= NOW() THEN SIGNAL 'échec trop ancien'
C’est inversé : si dateEtg + 6 mois >= maintenant, alors l’échec est récent, donc on ne doit pas rejeter. La condition correcte pour “trop ancien” est :

si dateEtg + 6 mois < NOW() => trop ancien.
“Avoir passé au moins 4 examens blancs” : le trigger calcule une moyenne sur les 4 meilleures notes, mais ne vérifie pas qu’il existe au moins 4 examens.

“25 séries de quiz” : le trigger compte des lignes dans Evaluer, ce qui correspond bien aux séries réalisées. En revanche, il utilise NEW.id :

Or, d’après le schéma relationnel (doc commun 1), la table Eleve est identifiée par idUtilisateur et les tables Evaluer(idEleve, ...) et Passer(idEleve, ...) référencent l’identifiant de l’élève.
Il faut donc vérifier la cohérence des clés et compter avec le bon identifiant (ex : NEW.idUtilisateur si c’est le nom de la colonne, sinon NEW.id si la table Eleve a bien une colonne id). => Risque : compter les séries/examens d’un mauvais élève, donc attribuer la garantie à tort.
“Garantie accordée une seule fois après le premier échec” : le trigger gère seulement le cas OLD.echecEtg = TRUE AND NEW.echecEtg = TRUE (donc un deuxième échec déclaré).
Mais la règle métier dit aussi que la garantie ne doit pas être attribuée deux fois, même si l’auto-école tente de réactiver le flag garantieReussite.
=> Il faut donc empêcher toute ré-attribution si OLD.garantieReussite est déjà à TRUE (contrôle sur le champ garantieReussite).
b) Corrections (parties à modifier/ajouter)

Extraits (en adaptant le nom de clé élève si besoin) :

SQL
-- empêcher une seconde attribution
IF OLD.garantieReussite = TRUE AND NEW.garantieReussite = TRUE THEN
    SIGNAL SQLSTATE '10006'
    SET MESSAGE_TEXT = 'Garantie réussite : déjà attribuée';
END IF;

-- test de date : trop ancien si dateETG + 6 mois < NOW()
IF DATE_ADD(NEW.dateEtg, INTERVAL 6 MONTH) < NOW() THEN
    SIGNAL SQLSTATE '10002'
    SET MESSAGE_TEXT = 'Garantie réussite : échec trop ancien';
END IF;

-- vérifier nb examens blancs >= 4
DECLARE v_nbExam INT;
SELECT COUNT(*) INTO v_nbExam FROM Passer WHERE idEleve = NEW.idUtilisateur;
IF v_nbExam < 4 THEN
    SIGNAL SQLSTATE '10004'
    SET MESSAGE_TEXT = 'Garantie réussite : nombre examens blancs insuffisant';
END IF;

-- adapter l'identifiant élève selon schéma relationnel
SELECT COUNT(*) INTO v_nbSerie FROM Evaluer WHERE idEleve = NEW.idUtilisateur;

SELECT AVG(examenScore) INTO v_scoreMoyen
FROM (
    SELECT examenScore
    FROM Passer
    WHERE idEleve = NEW.idUtilisateur
    ORDER BY examenScore DESC
    LIMIT 4
) AS MeilleureNotes;
Mission B2 – Traçage RGPD
B.2.1 – Schéma BD_RGPD_LOGS (proposition)
Objectif : journaliser qui (utilisateur + rôle) fait quoi (action) sur quelle donnée (table + id enregistrement) et quand.

Proposition minimale :

UtilisateurLog(idUtilisateur, nom, prenom) (ou uniquement idUtilisateur si on veut minimiser les données dupliquées)
Role(idRole, libele) : Directeur/Formateur/Élève/Modérateur
Action(idAction, libele) : CONSULTATION, INSERTION, MODIFICATION, SUPPRESSION
Evenement( idEvent PK, dateHeure DATETIME, idUtilisateur, idRole, idAction, tableCible VARCHAR, idEnregistrement INT, idAutoEcole INT NULL, details VARCHAR/TEXT NULL )
Remarques :

tableCible + idEnregistrement permettent de répondre aux questions du DPO.
idAutoEcole aide aux recherches “pour une auto-école donnée”.
details peut contenir des métadonnées non sensibles (ex : champs modifiés) sans stocker la donnée personnelle elle-même.
B.2.2 – Création utilisateur MySQL
Serveur Web : Easy2Drive.fr (hôte MySQL autorisé à se connecter).

SQL
CREATE USER 'APPLI_RGPD_LOGS'@'Easy2Drive.fr' IDENTIFIED BY 'MotDePasseSolideAChanger';
(Le mot de passe doit être fort et stocké dans un coffre/variable d’environnement côté appli.)

B.2.3 – Permission minimale (insert uniquement)
SQL
GRANT INSERT ON BD_RGPD_LOGS.* TO 'APPLI_RGPD_LOGS'@'Easy2Drive.fr';
B.2.4
a) Durée de conservation conforme CNIL

Doc CNIL 3 : période glissante ≤ 6 mois (sauf obligation légale/risque important).

=> Proposer : 6 mois.

b) Document RGPD où consigner la durée

Dans le registre des activités de traitement (registre RGPD / registre des traitements) qui doit mentionner les durées de conservation.

c) Solution technique de purge automatique (sans réalisation)

Mettre en place :

un événement planifié MySQL (EVENT SCHEDULER) qui supprime quotidiennement les logs plus vieux que 6 mois ; ou
un cron côté serveur exécutant une procédure stockée de purge.
Exemple de principe :

DELETE FROM Evenement WHERE dateHeure < DATE_SUB(NOW(), INTERVAL 6 MONTH);
Dossier C – Contre-mesures gestion des avis
Mission C1 – Saisie d’un avis
C1.1 – Méthode Eleve::getNbMaxAvisAtteint
On veut vrai si l’élève a déjà déposé 3 avis (tableau 0..3).

PHP
public function getNbMaxAvisAtteint(): bool
{
    return count($this->lesAvis) >= 3;
}
C1.2 – Contrôleur AvisEleveController::monAvis
Le formulaire ne doit être accessible que si :

soit l’élève n’a pas encore d’avis,
soit son dernier avis a été modéré et rejeté (modere = true mais publie = false),
et il ne doit pas avoir atteint 3 avis refusés.
Avec les seules méthodes visibles : getNbMaxAvisAtteint() et getDernierAvis()->getModere().

Condition de blocage (exemple cohérent) :

si l’élève a déjà un avis non modéré (en attente) => pas accès
ou si nb max atteint => pas accès
PHP
if ( $user->getNbMaxAvisAtteint() || (count($user->getLesAvis()) > 0 && $user->getDernierAvis()->getModere() == false) ) {
    return $this->redirectToRoute('home');
}
(Remarque : pour être totalement conforme au scénario, il faudrait aussi distinguer modéré et publié (rejet = modéré=true et publié=false) et compter le nombre d’avis refusés ; l’énoncé mentionne getNbAvisRefuse() dans le tableau modérateur, donc une implémentation complète s’appuierait idéalement sur cette information.)

C1.3 – Injection SQL
Injection fournie : elle ferme la chaîne et ajoute plusieurs tuples à l’INSERT.

a) Résultat dans la base après réussite

Au lieu d’insérer un seul avis, la requête injectée entraîne l’insertion de plusieurs avis supplémentaires (une liste de tuples) dans la table Avis, avec dateDepot = now(), et des champs forcés (publie=true, modere=true) ainsi qu’un idEleve imposé (ici 5 dans l’injection). On obtient donc plusieurs nouveaux enregistrements “validés” directement, sans passer par la modération normale.

b) Comment l’injection contourne les mesures précédentes

Les mesures prévoyaient de limiter l’élève à un avis en attente de modération et à 3 tentatives. Or l’injection permet :

de multiplier les insertions en une seule soumission ;
de forcer des champs (publie, modere) à true, contournant la modération ;
potentiellement d’usurper un autre élève (idEleve=5).
c) Solution de correction (sans réalisation)

Utiliser des requêtes préparées avec paramètres liés (PDO prepare() + bindParam()), et ne jamais concaténer l’entrée utilisateur dans SQL.

Ex :

INSERT INTO avis(contenu, dateDepot, publie, modere, idEleve) VALUES (:contenu, NOW(), :publie, :modere, :idEleve)
Et éventuellement :

validation/encodage côté serveur, journalisation des tentatives, et WAF/filtrage, mais la protection principale reste la requête paramétrée.
Mission C2 – Modération
C2.1 – PdoEasy2Drive::getDoublonMail
Objectif : vrai si l’email correspond à plusieurs élèves.

PHP
public function getDoublonMail($unEmail): bool
{
    $req = "SELECT COUNT(*) AS nb FROM utilisateur WHERE email = :mail";
    $res = PdoEasy2Drive::$monPdo->prepare($req);
    $res->bindParam(':mail', $unEmail);
    $res->execute();
    $ligne = $res->fetch();
    return ($ligne['nb'] >= 2);
}
(Remarque : si on veut limiter aux élèves : JOIN eleve ON eleve.idUtilisateur = utilisateur.id.)

C2.2 – AvisModerateurController::listeAvis
On doit transmettre à la vue une variable $doublonMail (ou une info par élève) indiquant si l’adresse est en double.

Dans la boucle :

PHP
$doublonMail = $PdoEasy2Drive->getDoublonMail($unEleve->getEmail());

$tabDernierAvisParEleve[] = [
    'leEleve' => $unEleve->getIdentite(),
    'avis' => $unEleve->getDernierAvis(),
    'nbRefus' => $unEleve->getNbAvisRefuse(),
    'pasDeNeph' => $pasDeNeph,
    'doublonMail' => $doublonMail
];
Et côté render, rien à changer si la vue exploite lesAvisAModerer.

Code
