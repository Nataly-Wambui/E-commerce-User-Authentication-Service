## User & Authentication Service
### Core Responsibilities:
User registration and profile management
Authentication and authorization (JWT)
Session management
User preferences and settings

## Service Architecture Document: User & Authentication Service
### Service Overview
The User & Authentication Service is a foundational component of the distributed e-commerce platform. It manages user identities, authentication, authorization, and profile data. The service ensures secure access to platform resources while protecting user privacy and maintaining data integrity.


### Goals
Provide secure onboarding and account management.
Authenticate users via JWT tokens and manage refresh sessions.
Enforce role-based access control (RBAC) for authorization.
Store user preferences and settings.
Ensure resilience with rate limiting, lockouts, and token refresh.


### Service Boundaries & Responsibilities
User Registration & Management (create, update, delete).
Authentication: login/logout, JWT issue & validation.
Authorization: RBAC (roles like customer, admin).
Session Management: refresh/expiration/invalidation.
User Preferences: simple settings.
Security: password hashing (bcrypt/argon2), token signing, and failed login lockout.


### Authentication Flow
Access tokens: short-lived (~15m).
Refresh tokens: long-lived (~7d), stored hashed in DB.
RBAC enforced via user_roles table.


## Database Schema Design
### users
id UUID (PK)
email VARCHAR(255) UNIQUE NOT NULL
username VARCHAR(100)
password_hash VARCHAR(255)

### user_roles
id UUID (PK)
user_id UUID (FK → users.id)
role_name VARCHAR(50)

### Indexes
users.email unique.
user_sessions.expires_at indexed for cleanup.

## Migration Strategy
Migrations managed via SQL files or ORM (Sequelize/Prisma).
Scripts run automatically on container start.

## Core API Endpoints (Critical Path)
### POST /register
Success → 201 Created with user ID.
Failure → 409 Conflict if email exists.

### POST /login
Success → 200 OK with access + refresh tokens.
Failure → 401 Unauthorized, wrong password, 403 Forbidden if locked.

### POST /refresh
Success → 200 OK with new access token.
Failure → 401 Unauthorized invalid/expired refresh.

### GET /profile
Success → 200 OK with user details.
Failure → 401 Unauthorized if no/invalid token.

### PUT /profile
Success → 200 OK with updated profile.
Failure → 400 Bad Requests or 401 Unauthorized.


## Basic Service Implementation (Skeleton)
This is = (skeleton + unit tests)

### /auth-service

  #### ├─ src/
  
  │   ├─ main.py              (startup)

  |

####  │   ├─ routes/
  
  │   │   ├─ auth.py          ( register, login, refresh token)
  
  │   │   └─ users.py         (get/update profile)

  |

  #### │   ├─ db/
  
  │   │   ├─ models.py        (User model)
  
  │   │   └─ migrations/    
  
  |
  
 #### │   ├─ security/
  
  │   │   ├─ jwt.py           (JWT sign/verify)
  
  │   │   └─ hash.py          (password hashing )
  
  │   ├─ middleware/
  
  | 
     
 #### │     ├─ tests/
  
  │   ├─ test_register.py    (covers new user + duplicate)
  
  │   ├─ test_login.py        (covers login success/fail)
  
  │   ├─ test_profile.py      (covers auth token usage)
  
  │
  
  ├─ Dockerfile   
  
  ├─ docker-compose.yml 
  
  ├─ README.md 
  
  └─ Makefile


## Unit Tests 
### Register
Should create a new user (201 Created).
Should fail on duplicate email (409 Conflict).

### Login
Should succeed with valid credentials (200 OK, returns JWT).
Should fail with the wrong password (401 Unauthorized).
Should fail if the account is disabled/locked (403 Forbidden).

### Profile
Should fail without a token (401 Unauthorized).
Should succeed with a valid token (200 OK, returns user details)

### Refresh 
Should succeed with a valid refresh token (200 OK, returns new access token).
Should fail with an invalid or expired refresh token (401 Unauthorized).

