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