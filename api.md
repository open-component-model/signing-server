# API Documentation for the Signing Server

## Overview

This API allows signing of content over an HTTP server. The API supports various endpoints for signing and managing certificates.

## Endpoints

### 1. Signing Content

**URL:** `/sign`

**Method:** `POST`

**Description:** This endpoint signs the provided content.

**Request:**

```json
{
  "data": "string",  // The content to be signed
  "hashAlgorithm": "string",  // The hash algorithm to use (optional)
  "encoding": "string"  // The encoding of the content (optional)
}
```

**Response:**

```json
{
  "signature": "string"  // The generated signature
}
```

### 2. Manage Certificates

**URL:** `/certificates`

**Method:** `GET`

**Description:** This endpoint returns the list of available certificates.

**Request:** None

**Response:**

```json
[
  {
    "id": "string",  // The certificate ID
    "subject": "string",  // The certificate subject
    "issuer": "string",  // The certificate issuer
    "validFrom": "string",  // Valid from
    "validTo": "string"  // Valid to
  }
]
```

### 3. Add Certificate

**URL:** `/certificates`

**Method:** `POST`

**Description:** This endpoint adds a new certificate.

**Request:**

```json
{
  "certificate": "string",  // The certificate in PEM format
  "privateKey": "string"  // The private key in PEM format
}
```

**Response:**

```json
{
  "message": "string"  // Success message
}
```

### Error Codes

- `400 Bad Request`: Invalid request
- `401 Unauthorized`: Unauthorized
- `500 Internal Server Error`: Server error

### Examples

Example Signature Request

**Request:**

```json
{
  "data": "Hello, World!",
  "hashAlgorithm": "SHA256",
  "encoding": "utf-8"
}
```

**Response:**

```json
{
  "signature": "MEUCIQDh...=="
}
```
