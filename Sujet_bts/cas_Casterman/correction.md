# Correction for BTS SIO U7 Cybersécurité BDPro Case Study (Dossiers A-D)

## SQL Trigger: majUtilisateur
```sql
CREATE TRIGGER majUtilisateur
AFTER INSERT ON utilisateurs
FOR EACH ROW
BEGIN
    SET NEW.date_modification = NOW();
END;
```

## Java Implementation: possedeDroit
```java
public boolean possedeDroit(String utilisateurId, String droit) {
    // Implementation of logic to check if user has the required rights
    ...
}
```

## Updated Java Log with IP
```java
public void logAction(String action, String utilisateurId) {
    String ipAddress = getClientIp(); // Function to get client IP
    System.out.println("[" + LocalDateTime.now() + "] Action: " + action + " by User: " + utilisateurId + " from IP: " + ipAddress);
}
```

## SQL Monitoring Query on Log
```sql
SELECT * FROM logs WHERE action = 'DELETE' AND timestamp >= NOW() - INTERVAL 1 HOUR;
```

## PHP API Delete Authorization Example
```php
if (!hasAuthorization($user, "delete")) {
    http_response_code(403);
    echo json_encode(["message" => "You are not authorized to perform this action."]);
    exit();
}
```

## Password Reset Best Practices
1. Require a strong password with a mix of characters.
2. Implement two-factor authentication.
3. Limit password reset attempts to prevent abuse.
4. Log password reset requests for auditing purposes.
5. Send reset confirmation emails to notify users of changes.
