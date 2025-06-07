# JWT Vulnerability Lab

A hands-on lab for learning about JWT (JSON Web Token) vulnerabilities and how to exploit them.

## Overview

This lab consists of:

- A Node.js backend API with intentional JWT vulnerabilities
- A MongoDB database for user storage
- A simple web frontend for interacting with the vulnerable API

## Vulnerabilities

This lab demonstrates the following JWT vulnerabilities:

1. Weak Secret Key
2. 'None' Algorithm Attack 
3. Algorithm Confusion Attack
4. Missing Signature Validation
5. JWT Secret Disclosure

## Getting Started

### Prerequisites

- Docker
- Docker Compose

### Setup

1. Clone this repository:
```
git clone <repository-url>
cd jwt-vulnerability-lab
```

2. Start the lab environment:
```
docker-compose up -d
```

3. Access the web application at http://localhost:8200
4. The API is accessible directly at http://localhost:3000

### Default Users

The lab is pre-configured with two users:
- Regular user: `user / userpassword`
- Admin user: `admin / adminpassword`

## Using the Lab

1. Register a new user or log in with one of the default users
2. Obtain a JWT token through the login process
3. Use the token to access protected endpoints
4. Analyze the token for vulnerabilities
5. Craft exploits for each vulnerability
6. Test your exploits against the vulnerable endpoints

## Vulnerabilities and Endpoints

- `/api/login` - Standard login endpoint (weak secret vulnerability)
- `/api/none-alg` - Vulnerable to 'none' algorithm attacks
- `/api/alg-confusion` - Vulnerable to algorithm confusion attacks
- `/api/missing-validation` - Vulnerable to signature tampering
- `/api/debug` - Leaks JWT secret
- `/api/secure` - Properly secured endpoint (for comparison)
- `/api/admin` - Admin-only endpoint (privilege escalation target)

## Solutions

Refer to the `solution.md` file for detailed explanations of each vulnerability, exploitation techniques, and recommended fixes.

## Disclaimer

This lab is for educational purposes only. The vulnerabilities demonstrated here should never be implemented in production systems.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 