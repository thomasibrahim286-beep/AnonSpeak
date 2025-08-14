;; AnonSpeak Contract - Simplified Version

;; constants
(define-constant contract-owner tx-sender)
(define-constant err-unauthorized (err u100))

;; data vars
(define-data-var feedback-counter uint u0)
(define-data-var contract-paused bool false)

;; Submit feedback
(define-public (submit-feedback 
  (encrypted-content (buff 64))
  (proof-hash (buff 32))
  (submitter-hash (buff 32))
  (stx-holdings-proof uint)
  (gaia-url (optional (string-ascii 256))))
  (ok u1)
)

;; Get feedback counter
(define-read-only (get-feedback-counter)
  (var-get feedback-counter)
)
