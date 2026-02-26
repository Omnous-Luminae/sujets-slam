# Correction — BTS SIO U7 Cybersécurité (Cas Casterman / BDPro) — Dossiers A à D

> Correction rédigée à partir du sujet `25si7slam_sujet.txt` et des extraits du dossier documentaire inclus dans ce fichier.

---

## DOSSIER A — Participation à l’atelier d’analyse des risques

### Mission A1 — Évaluation des risques à partir des récits utilisateurs (Doc A1)

Doc A1 qualifie les besoins selon : **Disponibilité / Intégrité / Confidentialité / Preuve**.

#### User story 1
**« En tant qu’éditeur de bande dessinée, j'enregistre les informations d’une nouvelle bande dessinée et je numérise un contrat passé avec un auteur. »**
- **Disponibilité :** *modéré* (*)
- **Intégrité :** *important* (**)
- **Confidentialité :** *important* (**)
- **Preuve :** *important* (**)

Risques principaux :
- Altération des données (ISBN, auteurs, contrats) → erreurs juridiques/commerciales.
- Fuite de contrats numérisés et données auteurs (adresse, téléphone, mail).
- Absence de traçabilité en cas de litige.

Mesures attendues (exemples) :
- Contrôle d’accès par rôle.
- Journalisation des opérations sensibles (création, modification, suppression) avec horodatage.
- Sauvegardes régulières et tests de restauration.

#### User story 2
**« En tant qu’assistant d’édition, je consulte les informations d’une bande dessinée. »**
- **Disponibilité :** *modéré* (*)
- **Intégrité :** *important* (**)
- **Confidentialité :** *important* (**)
- **Preuve :** *sans objet* (-) selon le document.

Mesures attendues :
- Accès en lecture seule.
- Limitation des exports/impressions si nécessaire.

#### User story 3
**« En tant qu’éditeur de bande dessinée, je transmets une bande dessinée finale au format PDF à l’imprimeur. »**
- **Disponibilité :** *modéré* (*)
- **Intégrité :** *important* (**)
- **Confidentialité :** *important* (**)
- **Preuve :** *important* (**)

Mesures attendues :
- Transfert via canal chiffré et authentifié (SFTP/HTTPS).
- Signature/empreinte du PDF final (GPG), conservation des preuves.
- Journalisation des actions (qui, quoi, quand, depuis où).

---

### Mission A2 — Gestion d’un événement redouté : attaque par rançongiciel

Impacts typiques :
- **Disponibilité :** arrêt de BDPro (base chiffrée/inaccessible).
- **Intégrité :** risques de corruption de données lors de l’attaque ou de la restauration.
- **Confidentialité :** exfiltration possible (double extorsion).
- **Preuve :** logs chiffrés/effacés → perte de traçabilité.

Mesures (prévention/résilience) :
- Sauvegardes **3-2-1** (dont une copie hors-ligne/immutable) + tests de restauration.
- Moindre privilège (droits par fonction, comptes techniques séparés).
- Durcissement Windows, patch management, EDR/antivirus.
- Segmentation réseau.
- Centralisation/collecte des journaux.

Obligations en cas de violation de données (RGPD, synthèse) :
- Notification à l’autorité de contrôle (CNIL) dans les **72h** si la violation est susceptible d’engendrer un risque.
- Information des personnes concernées si le risque est **élevé**.
- Documentation de l’incident (registre interne des violations).

---

## DOSSIER B — Sécurisation du progiciel BDPro

### Mission B1 — Amélioration de la sécurité de l’authentification

Constat : les mots de passe sont stockés en clair → non conforme aux bonnes pratiques.

Correction attendue :
- Stocker un **hash** (non réversible) du mot de passe (idéalement avec un sel et un algo adapté : bcrypt/argon2/scrypt).
- Au login : comparer le hash du mot de passe saisi avec la valeur stockée.

Remarque : une longueur minimale de 6 caractères est trop faible. Recommander une politique plus robuste (longueur, anti-mots de passe courants, limitation des essais, etc.).

---

### Mission B2 — Trigger `majUtilisateur` (politique des 6 mois + interdiction des 5 derniers)

Attendu : lors d’un **UPDATE** de `Utilisateur` si `mdpActuel` change :
- appeler `mdpExisteHisto` ;
- si `false` : archiver l’ancien mdp dans `HistoMotDePasse`, conserver **les 5 derniers**, mettre à jour `dateHeureMdpActuel` à maintenant ;
- sinon : refuser via `SIGNAL`.

Problème observé : `HistoMotDePasse` reste vide.

Causes probables dans le trigger fourni (Doc B2) :
- `v_nb` non déclaré.
- suppression de l’entrée la plus ancienne faite sans condition `IF v_nb > 5`.

Trigger corrigé :

```sql
DELIMITER $$

CREATE TRIGGER majUtilisateur
BEFORE UPDATE ON Utilisateur
FOR EACH ROW
BEGIN
    DECLARE correct BOOLEAN DEFAULT TRUE;
    DECLARE v_nb INT DEFAULT 0;

    IF (OLD.mdpActuel <> NEW.mdpActuel) THEN

        IF (mdpExisteHisto(NEW.mdpActuel, OLD.id) = FALSE) THEN

            INSERT INTO HistoMotDePasse(idUtilisateur, dateHeureChangeMdp, motDePasse)
            VALUES (OLD.id, OLD.dateHeureMdpActuel, OLD.mdpActuel);

            SELECT COUNT(*) INTO v_nb
            FROM HistoMotDePasse
            WHERE idUtilisateur = OLD.id;

            IF (v_nb > 5) THEN
                DELETE FROM HistoMotDePasse
                WHERE idUtilisateur = OLD.id
                  AND dateHeureChangeMdp = (
                      SELECT MIN(x.dateHeureChangeMdp)
                      FROM (
                          SELECT dateHeureChangeMdp
                          FROM HistoMotDePasse
                          WHERE idUtilisateur = OLD.id
                      ) x
                  );
            END IF;

            SET NEW.dateHeureMdpActuel = SYSDATE();

        ELSE
            SET correct = FALSE;
        END IF;
    END IF;

    IF (correct = FALSE) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'mot de passe incorrect';
    END IF;
END$$

DELIMITER ;
```

---

### Mission B3 — Sécurisation des bandes dessinées au format PDF

Attendu (Doc B3) : mémoriser pour chaque PDF :
- nom complet, date de création, chemin d’accès ;
- utilisateur générateur + BD concernée ;
- signature électronique (GPG) pour le document final ;
- conserver toutes les versions (traçabilité).

Proposition de table (exemple) :

```sql
CREATE TABLE PdfBandeDessinee (
  idPdf INT AUTO_INCREMENT PRIMARY KEY,
  isbn VARCHAR(20) NOT NULL,
  idUtilisateur INT NOT NULL,
  nomFichier VARCHAR(255) NOT NULL,
  cheminFichier VARCHAR(500) NOT NULL,
  dateCreation DATETIME NOT NULL,
  estFinal BOOLEAN NOT NULL DEFAULT FALSE,
  signatureGpg TEXT NULL,
  FOREIGN KEY (isbn) REFERENCES BandeDessinee(isbn),
  FOREIGN KEY (idUtilisateur) REFERENCES Utilisateur(id)
);
```

Transfert du PDF final (2 Go) :
- éviter l’email ; utiliser **SFTP** ou **HTTPS** (TLS) avec authentification.
- idéalement chiffrer/signature côté fichier (GPG) + conserver preuve d’envoi.

---

## DOSSIER C — Gestion des droits et accès à la base

### Mission C1 — Contrôle des droits d’accès : `possedeDroit`

Implémentation attendue (compatible avec les tests unitaires Doc C5) :

```java
public boolean possedeDroit(String uneTable, String uneOperation) {
    for (Droit unDroit : this.laFonction.getLesDroits()) {
        if (unDroit.getNomTableBdd().equals(uneTable)
                && unDroit.getNomOperation().equals(uneOperation)) {
            return true;
        }
    }
    return false;
}
```

---

### Mission C2 — Logs : ajout de l’IP + requêtes de surveillance

#### Ajout de l’adresse IP à `creerEnregLog` (Doc C6)

```java
public void creerEnregLog(Utilisateur util, Droit droit, DateTime date, String ip){
    SimpleDateFormat forme = new SimpleDateFormat("dd/MM/yyyy-HH:mm:ss");
    String strDate = forme.format(date);

    String messageLog = "util:" + util.getIdUtilisateur();
    messageLog += ";operation:" + droit.getNomOperation();
    messageLog += ";table:" + droit.getNomTableBdd();
    messageLog += ";date:" + strDate;
    messageLog += ";ip:" + ip;

    logger.info(messageLog);
}
```

#### Requête SQL demandée (table Log)

Nombre d’insert dans `BandeDessinee` depuis 08:00, pour chaque utilisateur ayant fait plus de 5 ajouts :

```sql
SELECT idUtilisateur, COUNT(*) AS nbAjouts
FROM Log
WHERE nomTable = 'BandeDessinee'
  AND operation = 'insert'
  AND dateHeure >= CONCAT(CURRENT_DATE(), ' 08:00:00')
GROUP BY idUtilisateur
HAVING COUNT(*) > 5;
```

---

## DOSSIER D — Mise en ligne de la base et gestion des accès (API REST)

### Mission D1 — Contrôle des accès dangereux (DELETE/PUT)

Attendu : contrôler côté API les opérations dangereuses via `autoriseAction(idUtilisateur, operation, table)` (Doc D2).

Exemple de sécurisation de `delete()` dans `Controle.php` (Doc D3) :

```php
public function delete(string $table, array $champs): void {

    if (!isset($champs['idUtilisateur'])) {
        $this->reponse(400, []);
        return;
    }
    $idUtil = strval($champs['idUtilisateur']);

    if (!$this->accessBdd->autoriseAction($idUtil, "delete", $table)) {
        $this->reponse(403, []);
        return;
    }

    $result = $this->accessBdd->delete($table, $champs);
    $this->reponse(204, $result);
}
```

Les autres méthodes (PUT/POST/GET) devront être adaptées ensuite selon le même modèle.

---

### Mission D2 — Catalogue JSON en accès libre

Solution retenue : créer une **API publique distincte** en lecture seule.

Bonnes pratiques :
- n’exposer que des routes **GET** (pas de PUT/DELETE/POST).
- exposer uniquement les champs nécessaires (pas de données personnelles).
- rate limiting, cache et supervision.

---

### Mission D3 — Mot de passe oublié : sécurisation

Le mode opératoire prévu (envoi d’un mot de passe par mail) est risqué.

Correction attendue :
- demander l’email ; répondre de façon générique.
- générer un **token** de réinitialisation aléatoire, à durée courte, stocké (hashé) en base.
- envoyer un lien de réinitialisation (HTTPS).
- l’utilisateur choisit un nouveau mot de passe ; token invalidé après usage.
- limiter les tentatives et journaliser l’opération.