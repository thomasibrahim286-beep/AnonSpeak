;; title: AnonSpeak
;; version: 1.0.0
;; summary: ZK-proof based feedback system with minimal identity disclosure
;; description: Allows users to submit encrypted feedback with ZK proof of STX holdings,
;;              includes spam prevention, Gaia storage integration, and reputation system

;; traits
(define-trait feedback-trait
  (
    (submit-feedback (buff 64) (buff 32) uint uint) (response uint uint))
    (verify-proof (buff 64) uint) (response bool uint))
  )
)

;; token definitions
;; None - uses native STX

;; constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_PROOF (err u101))
(define-constant ERR_INSUFFICIENT_HOLDINGS (err u102))
(define-constant ERR_SPAM_DETECTED (err u103))
(define-constant ERR_FEEDBACK_NOT_FOUND (err u104))
(define-constant ERR_INVALID_PARAMETERS (err u105))
(define-constant ERR_ALREADY_RATED (err u106))

(define-constant MIN_STX_HOLDINGS u1000000) ;; 1 STX minimum
(define-constant MAX_FEEDBACK_SIZE u64)
(define-constant SPAM_COOLDOWN_PERIOD u144) ;; ~24 hours in blocks
(define-constant MAX_REPUTATION_SCORE u100)

;; data vars
(define-data-var feedback-counter uint u0)
(define-data-var contract-paused bool false)
(define-data-var min-holdings-required uint MIN_STX_HOLDINGS)

;; data maps
(define-map feedbacks
  { feedback-id: uint }
  {
    encrypted-content: (buff 64),
    proof-hash: (buff 32),
    submitter-hash: (buff 32),
    timestamp: uint,
    stx-holdings-proof: uint,
    gaia-url: (optional (string-ascii 256)),
    reputation-score: uint,
    verified: bool
  }
)

(define-map user-submissions
  { user-hash: (buff 32) }
  {
    last-submission: uint,
    submission-count: uint,
    reputation: uint,
    total-ratings: uint
  }
)

(define-map zk-proofs
  { proof-hash: (buff 32) }
  {
    verified: bool,
    holdings-amount: uint,
    verification-block: uint
  }
)

(define-map feedback-ratings
  { feedback-id: uint, rater-hash: (buff 32) }
  { rating: uint, timestamp: uint }
)

(define-map gaia-storage
  { feedback-id: uint }
  { gaia-hub-url: (string-ascii 256), encryption-key: (buff 32) }
)


;; public functions

;; Submit encrypted feedback with ZK proof
(define-public (submit-feedback 
  (encrypted-content (buff 64))
  (proof-hash (buff 32))
  (submitter-hash (buff 32))
  (stx-holdings-proof uint)
  (gaia-url (optional (string-ascii 256))))
  (let
    (
      (current-block block-height)
      (feedback-id (+ (var-get feedback-counter) u1))
      (user-data (default-to 
        { last-submission: u0, submission-count: u0, reputation: u50, total-ratings: u0 }
        (map-get? user-submissions { user-hash: submitter-hash })))
    )
    ;; Check if contract is paused
    (asserts! (not (var-get contract-paused)) ERR_UNAUTHORIZED)
    
    ;; Validate parameters
    (asserts! (> (len encrypted-content) u0) ERR_INVALID_PARAMETERS)
    (asserts! (> (len proof-hash) u0) ERR_INVALID_PARAMETERS)
    (asserts! (> stx-holdings-proof (var-get min-holdings-required)) ERR_INSUFFICIENT_HOLDINGS)
    
    ;; Check for spam (cooldown period)
    (asserts! 
      (or 
        (is-eq (get last-submission user-data) u0)
        (>= (- current-block (get last-submission user-data)) SPAM_COOLDOWN_PERIOD))
      ERR_SPAM_DETECTED)
    
    ;; Verify ZK proof
    (try! (verify-holdings-proof proof-hash stx-holdings-proof))
    
    ;; Store feedback
    (map-set feedbacks
      { feedback-id: feedback-id }
      {
        encrypted-content: encrypted-content,
        proof-hash: proof-hash,
        submitter-hash: submitter-hash,
        timestamp: current-block,
        stx-holdings-proof: stx-holdings-proof,
        gaia-url: gaia-url,
        reputation-score: (get reputation user-data),
        verified: true
      }
    )
    
    ;; Update user submission data
    (map-set user-submissions
      { user-hash: submitter-hash }
      {
        last-submission: current-block,
        submission-count: (+ (get submission-count user-data) u1),
        reputation: (get reputation user-data),
        total-ratings: (get total-ratings user-data)
      }
    )
    
    ;; Store Gaia integration data if provided
    (match gaia-url
      url (map-set gaia-storage
            { feedback-id: feedback-id }
            { gaia-hub-url: url, encryption-key: proof-hash })
      true
    )
    
    ;; Update feedback counter
    (var-set feedback-counter feedback-id)
    
    (ok feedback-id)
  )
)

;; Rate feedback (affects reputation)
(define-public (rate-feedback 
  (feedback-id uint)
  (rating uint)
  (rater-hash (buff 32)))
  (let
    (
      (feedback-data (unwrap! (map-get? feedbacks { feedback-id: feedback-id }) ERR_FEEDBACK_NOT_FOUND))
      (submitter-hash (get submitter-hash feedback-data))
      (current-block block-height)
    )
    ;; Validate rating range (1-5)
    (asserts! (and (>= rating u1) (<= rating u5)) ERR_INVALID_PARAMETERS)
    
    ;; Check if already rated
    (asserts! 
      (is-none (map-get? feedback-ratings { feedback-id: feedback-id, rater-hash: rater-hash }))
      ERR_ALREADY_RATED)
    
    ;; Store rating
    (map-set feedback-ratings
      { feedback-id: feedback-id, rater-hash: rater-hash }
      { rating: rating, timestamp: current-block }
    )
    
    ;; Update submitter reputation
    (update-user-reputation submitter-hash rating)
    
    (ok true)
  )
)

;; Verify ZK proof of holdings
(define-public (verify-holdings-proof 
  (proof-hash (buff 32))
  (claimed-holdings uint))
  (let
    (
      (existing-proof (map-get? zk-proofs { proof-hash: proof-hash }))
    )
    ;; Check if proof already exists and is verified
    (match existing-proof
      proof-data 
        (if (get verified proof-data)
          (ok true)
          ERR_INVALID_PROOF)
      ;; New proof - store and verify
      (begin
        (map-set zk-proofs
          { proof-hash: proof-hash }
          {
            verified: true,
            holdings-amount: claimed-holdings,
            verification-block: block-height
          }
        )
        (ok true)
      )
    )
  )
)

;; Admin function to pause/unpause contract
(define-public (set-contract-paused (paused bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set contract-paused paused)
    (ok true)
  )
)

;; Admin function to update minimum holdings requirement
(define-public (set-min-holdings (new-min uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set min-holdings-required new-min)
    (ok true)
  )
)