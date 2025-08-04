#  Vulnerability Report - WebGoat

##  Εντοπισμένα Alerts

| Severity | Είδος Ευπάθειας     | Αρχείο                          | Περιγραφή                                      | Link στο CVE |
|----------|---------------------|----------------------------------|------------------------------------------------|----------------|
| Critical | [1] XML External Entity (XXE)      | `CommentsCache.java:79`| Ανεπαρκής XML config | [[Alert](https://cwe.mitre.org/data/definitions/611.html)]     |
| Critical | [2] Insecure Deserialization    | `VulnerableComponentsLesson.java:42` | Εκτελέσιμο περιεχόμενο | [[Alert](https://cwe.mitre.org/data/definitions/502.html) ]    |
| Critical | [3] Insecure Deserialization   | `InsecureDeserializationTask.java:45` | Πανομοιότυπη | [[Alert](https://cwe.mitre.org/data/definitions/502.html)]     |
| Critical | [4] Server-side request forgery  |  `SSRFTask2.java:36`  | Χωρίς έλεγχο URL | [[Alert](https://cwe.mitre.org/data/definitions/918.html) ]    |
| High     | [5] Missing JWT signature check  | `TokenTest.java:39`  |  Χωρίς επαλήθευση  | [[Alert](https://cwe.mitre.org/data/definitions/347.html)]     |
| High     | [6] Insecure randomness  | `JWTRefreshEndpoint.java:77`  |  Προβλέψιμο token  | [[Alert](https://cwe.mitre.org/data/definitions/330.html)]    |
| High     | [7] Query built from user-controlled sources | `Servers.java:51`  |  Ευάλωτο query  | [[Alert](https://cwe.mitre.org/data/definitions/89.html)]    |

---

##  Προτεινόμενα Μέτρα Αντιμετώπισης

### [1] XML External Entity  CWE-611
####  Περιγραφή
Η εφαρμογή χρησιμοποιεί `DocumentBuilderFactory` για ανάλυση XML δεδομένων, χωρίς να απενεργοποιεί την επεξεργασία εξωτερικών οντοτήτων. 
Αυτό την καθιστά ευάλωτη σε επιθέσεις τύπου XXE, οι οποίες μπορούν να οδηγήσουν σε:

- Ανάγνωση ευαίσθητων αρχείων του συστήματος 
- Επιθέσεις SSRF (Server-Side Request Forgery)
- Κατάρρευση του parser μέσω entity expansion (DoS)

#### Απόσπασμα Κώδικα 
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(input);
```
- Πρέπει να απενεργοποιηθεί η υποστήριξη για external entities

### [2] Insecure Deserialization CWE-502
#### Περιγραφή 
Η εφαρμογή χρησιμοποιεί τη μέθοδο `ObjectInputStream` για την αποσειριοποίηση δεδομένων που προέρχονται από τον χρήστη, χωρίς έλεγχο τύπου ή φιλτράρισμα.
Αυτό επιτρέπει την εκτέλεση κακόβουλου κώδικα μέσω ειδικά κατασκευασμένων Java αντικειμένων.

#### Απόσπασμα Κώδικα 
```java
ObjectInputStream in = new ObjectInputStream(req.getInputStream());
Object obj = in.readObject();
```
- Χρήση των type filters
- Χρήση ασφαλέστερων formats

### [3] Insecure Deserialization CWE-502 
#### Περιγραφή 
Η ευπάθεια είναι πανομοιότυπη με την προηγούμενη

#### Απόσπασμα Κώδικα 
```java
ObjectInputStream in = new ObjectInputStream(req.getInputStream());
Object obj = in.readObject();
```
- Ίδια λύση με την Ευπάθεια 2

### [4] Server-side request forgery CWE-918
#### Περιγραφή
Η εφαρμογή επιτρέπει στον χρήστη να καθορίσει διεύθυνση URL που θα χρησιμοποιηθεί για απομακρυσμένο request, χωρίς κανένα φίλτρο ή έλεγχο.
Αυτό επιτρέπει στον επιτιθέμενο να στείλει αιτήματα προς εσωτερικές υπηρεσίες ή IPs

#### Απόσπασμα Κώδικα 
```java
URL url = new URL(request.getParameter("url"));
URLConnection connection = url.openConnection();
```
- Περιορισμός των επιτρεπόμενων URLs
- Εφαρμογή blacklist για IP ranges
- Χρήση DNS resolution και filtering στη server πλευρά

### [5] Missing JWT signature check CWE-347
#### Περιγραφή 
Ο έλεγχος εγκυρότητας του JWT token παραλείπει την επαλήθευση της υπογραφής, με αποτέλεσμα να μπορεί ένας χρήστης να τροποποιήσει το payload και να παρακάμψει αυθεντικοποίηση/εξουσιοδότηση.

#### Απόσπασμα Κώδικα 
```java
Claims claims = Jwts.parser().parseClaimsJwt(jwtToken).getBody();
```
- Πρέπει να χρησιμοποιείται η `parseClaimsJws` με έλεγχο υπογραφής

### [6] Insecure randomness CWE-330
#### Περιγραφή
Η ευπάθεια προκύπτει από τη χρήση μη-ασφαλών γεννητριών τυχαίων αριθμών για την παραγωγή tokens. 
Αυτό καθιστά εφικτή την πρόβλεψη των τιμών και παραβιάζει την ασφάλεια της αυθεντικοποίησης.

#### Απόσπασμα Κώδικα 
```java
Random r = new Random();
String token = Long.toHexString(r.nextLong());
```
#### Λύση
- Χρήση `PreparedStatement` για binding παραμέτρων

### [7] Query built from user-controlled sources  CWE-89
#### Περιγραφή
Η εφαρμογή χτίζει SQL queries από user input χωρίς καμία επεξεργασία ή binding, εκθέτοντας τη βάση δεδομένων σε SQL Injection επιθέσεις.

#### Απόσπασμα Κώδικα 
```java
String query = "SELECT * FROM servers WHERE name = '" + userInput + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);
```
#### Λύση
- Χρήση `SecureRandom` για κρυπτογραφικά ασφαλή token generation
