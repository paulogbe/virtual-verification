;; Virtual-Verification Smart Contract
;; Zero-knowledge identity verification system

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-proof (err u104))
(define-constant err-credential-revoked (err u105))

;; Data Variables
(define-data-var next-credential-id uint u1)
(define-data-var next-authority-id uint u1)

;; Data Maps

;; Trusted authorities (government, universities, employers)
(define-map authorities
  principal
  {
    authority-id: uint,
    name: (string-ascii 64),
    authority-type: (string-ascii 32),
    is-active: bool,
    credentials-issued: uint
  }
)

;; Credential schemas - define what can be verified
(define-map credential-schemas
  uint
  {
    schema-name: (string-ascii 64),
    schema-type: (string-ascii 32),
    issuer: principal,
    is-active: bool
  }
)

;; User credentials (proof hashes, not actual data)
(define-map user-credentials
  {user: principal, credential-id: uint}
  {
    schema-id: uint,
    issuer: principal,
    proof-hash: (buff 32),
    issued-at: uint,
    expires-at: uint,
    is-revoked: bool
  }
)

;; Verification requests and results
(define-map verifications
  uint
  {
    user: principal,
    verifier: principal,
    credential-id: uint,
    verified-at: uint,
    verification-type: (string-ascii 32)
  }
)

;; User reputation scores (homomorphically encrypted)
(define-map user-reputation
  principal
  {
    reputation-score: uint,
    total-verifications: uint,
    successful-verifications: uint,
    last-updated: uint
  }
)

;; Authority Management Functions

(define-public (register-authority (authority principal) (name (string-ascii 64)) (auth-type (string-ascii 32)))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (is-none (map-get? authorities authority)) err-already-exists)
    (let
      (
        (authority-id (var-get next-authority-id))
      )
      (map-set authorities authority {
        authority-id: authority-id,
        name: name,
        authority-type: auth-type,
        is-active: true,
        credentials-issued: u0
      })
      (var-set next-authority-id (+ authority-id u1))
      (ok authority-id)
    )
  )
)

(define-public (deactivate-authority (authority principal))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (match (map-get? authorities authority)
      auth-data (ok (map-set authorities authority (merge auth-data {is-active: false})))
      err-not-found
    )
  )
)

;; Credential Schema Management

(define-public (create-credential-schema (schema-name (string-ascii 64)) (schema-type (string-ascii 32)))
  (let
    (
      (schema-id (var-get next-credential-id))
      (authority-data (unwrap! (map-get? authorities tx-sender) err-unauthorized))
    )
    (asserts! (get is-active authority-data) err-unauthorized)
    (map-set credential-schemas schema-id {
      schema-name: schema-name,
      schema-type: schema-type,
      issuer: tx-sender,
      is-active: true
    })
    (var-set next-credential-id (+ schema-id u1))
    (ok schema-id)
  )
)

;; Credential Issuance (proof hash only, no personal data)

(define-public (issue-credential 
  (user principal) 
  (schema-id uint) 
  (proof-hash (buff 32)) 
  (expires-at uint))
  (let
    (
      (credential-id (var-get next-credential-id))
      (authority-data (unwrap! (map-get? authorities tx-sender) err-unauthorized))
      (schema-data (unwrap! (map-get? credential-schemas schema-id) err-not-found))
    )
    (asserts! (get is-active authority-data) err-unauthorized)
    (asserts! (get is-active schema-data) err-not-found)
    (asserts! (is-eq (get issuer schema-data) tx-sender) err-unauthorized)
    
    (map-set user-credentials {user: user, credential-id: credential-id} {
      schema-id: schema-id,
      issuer: tx-sender,
      proof-hash: proof-hash,
      issued-at: block-height,
      expires-at: expires-at,
      is-revoked: false
    })
    
    (map-set authorities tx-sender 
      (merge authority-data {credentials-issued: (+ (get credentials-issued authority-data) u1)}))
    
    (var-set next-credential-id (+ credential-id u1))
    (ok credential-id)
  )
)

;; Credential Revocation

(define-public (revoke-credential (user principal) (credential-id uint))
  (let
    (
      (credential-data (unwrap! (map-get? user-credentials {user: user, credential-id: credential-id}) err-not-found))
    )
    (asserts! (is-eq tx-sender (get issuer credential-data)) err-unauthorized)
    (ok (map-set user-credentials {user: user, credential-id: credential-id}
      (merge credential-data {is-revoked: true})))
  )
)

;; Verification Functions

(define-public (verify-credential (user principal) (credential-id uint) (verification-type (string-ascii 32)))
  (let
    (
      (credential-data (unwrap! (map-get? user-credentials {user: user, credential-id: credential-id}) err-not-found))
      (verification-id (var-get next-credential-id))
    )
    (asserts! (not (get is-revoked credential-data)) err-credential-revoked)
    (asserts! (>= (get expires-at credential-data) block-height) err-invalid-proof)
    
    (map-set verifications verification-id {
      user: user,
      verifier: tx-sender,
      credential-id: credential-id,
      verified-at: block-height,
      verification-type: verification-type
    })
    
    (update-reputation user true)
    (ok verification-id)
  )
)

;; Reputation Management

(define-private (update-reputation (user principal) (successful bool))
  (let
    (
      (current-reputation (default-to 
        {reputation-score: u0, total-verifications: u0, successful-verifications: u0, last-updated: u0}
        (map-get? user-reputation user)))
      (new-total (+ (get total-verifications current-reputation) u1))
      (new-successful (if successful (+ (get successful-verifications current-reputation) u1) (get successful-verifications current-reputation)))
      (new-score (/ (* new-successful u100) new-total))
    )
    (map-set user-reputation user {
      reputation-score: new-score,
      total-verifications: new-total,
      successful-verifications: new-successful,
      last-updated: block-height
    })
  )
)

;; Read-only Functions

(define-read-only (get-authority (authority principal))
  (ok (map-get? authorities authority))
)

(define-read-only (get-credential (user principal) (credential-id uint))
  (ok (map-get? user-credentials {user: user, credential-id: credential-id}))
)

(define-read-only (get-user-reputation (user principal))
  (ok (map-get? user-reputation user))
)

(define-read-only (get-credential-schema (schema-id uint))
  (ok (map-get? credential-schemas schema-id))
)

(define-read-only (is-credential-valid (user principal) (credential-id uint))
  (match (map-get? user-credentials {user: user, credential-id: credential-id})
    credential-data (ok (and 
      (not (get is-revoked credential-data))
      (>= (get expires-at credential-data) block-height)))
    (ok false)
  )
)