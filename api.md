# API-Dokumentation für den Signing-Server

## Übersicht

Diese API ermöglicht das Signieren von Inhalten über einen HTTP-Server. Die API unterstützt verschiedene Endpunkte für das Signieren und Verwalten von Zertifikaten.

## Endpunkte

### 1. Signieren von Inhalten

**URL:** `/sign`

**Methode:** `POST`

**Beschreibung:** Dieser Endpunkt signiert den bereitgestellten Inhalt.

**Anfrage:**

```json
{
  "data": "string",  // Der zu signierende Inhalt
  "hashAlgorithm": "string",  // Der zu verwendende Hash-Algorithmus (optional)
  "encoding": "string"  // Die Kodierung des Inhalts (optional)
}
```

**Antwort:**

```json
{
  "signature": "string"  // Die generierte Signatur
}
```

### 2. Zertifikate verwalten

**URL:** `/certificates`

**Methode:** `GET`

**Beschreibung:** Dieser Endpunkt gibt die Liste der verfügbaren Zertifikate zurück.

**Anfrage:** Keine

**Antwort:**

```json
[
  {
    "id": "string",  // Die ID des Zertifikats
    "subject": "string",  // Der Betreff des Zertifikats
    "issuer": "string",  // Der Aussteller des Zertifikats
    "validFrom": "string",  // Gültig ab
    "validTo": "string"  // Gültig bis
  }
]
```

### 3. Zertifikat hinzufügen

**URL:** `/certificates`

**Methode:** `POST`

**Beschreibung:** Dieser Endpunkt fügt ein neues Zertifikat hinzu.

**Anfrage:**

```json
{
  "certificate": "string",  // Das Zertifikat im PEM-Format
  "privateKey": "string"  // Der private Schlüssel im PEM-Format
}
```

***Antwort:***

```json
{
  "message": "string"  // Erfolgsmeldung
}
```

### Fehlercodes

- `400 Bad Request`: Ungültige Anfrage
- `401 Unauthorized`: Nicht autorisiert
- `500 Internal Server Error`: Serverfehler

### Beispiele

**Beispiel für eine Signaturanfrage**

*Anfrage:**

```json
{
  "data": "Hello, World!",
  "hashAlgorithm": "SHA256",
  "encoding": "utf-8"
}
```

<vscode_annotation details='%5B%7B%22title%22%3A%22hardcoded-credentials%22%2C%22description%22%3A%22Embedding%20credentials%20in%20source%20code%20risks%20unauthorized%20access%22%7D%5D'></vscode_annotation>

**Antwort:**

```json
{
  "signature": "MEUCIQDh...=="
}
```
