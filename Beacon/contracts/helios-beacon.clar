;; Verifiable Random Beacon Service
;; A secure random number generation service using commit-reveal pattern

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant VALIDATOR_STAKE u1000000000) ;; 1000 STX in microSTX
(define-constant COMMIT_WINDOW u180) ;; 3 minutes in blocks (~10s per block)
(define-constant REVEAL_WINDOW u60) ;; 1 minute in blocks
(define-constant MIN_VALIDATORS u3)
(define-constant MAX_VALIDATORS u5)

;; Error codes
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_INVALID_STAKE (err u101))
(define-constant ERR_TOO_MANY_VALIDATORS (err u102))
(define-constant ERR_COMMIT_PHASE_ENDED (err u103))
(define-constant ERR_REVEAL_PHASE_ENDED (err u104))
(define-constant ERR_ALREADY_COMMITTED (err u105))
(define-constant ERR_NO_COMMITMENT_FOUND (err u106))
(define-constant ERR_INVALID_REVEAL (err u107))
(define-constant ERR_NOT_ENOUGH_VALIDATORS (err u108))

;; Data vars
(define-data-var current-request-id uint u0)
(define-data-var current-phase (string-ascii 10) "none") ;; none, commit, reveal
(define-data-var phase-start-block uint u0)
(define-data-var validator-count uint u0)

;; Data maps
(define-map validators principal bool)
(define-map commitments 
    { request-id: uint, validator: principal }
    { commitment: (buff 32), revealed: bool, value: (optional (buff 32)) })
(define-map random-seeds uint (buff 32))
(define-map validator-stakes principal uint)

;; Private functions
(define-private (hash-values (value-1 (buff 32)) (value-2 (buff 32)))
    (sha256 (concat value-1 value-2)))

(define-private (verify-commitment 
    (commitment (buff 32))
    (revealed-value (buff 32))
    (validator principal))
    (let ((stored-commitment (unwrap! 
        (get commitment 
            (map-get? commitments { request-id: (var-get current-request-id), validator: validator }))
        false)))
        (is-eq commitment (sha256 revealed-value))))

(define-private (combine-revealed-values (acc (buff 32)) (next (buff 32)))
    (sha256 (concat acc next)))

(define-private (slash-validator (validator principal))
    (begin
        (map-delete validator-stakes validator)
        (map-delete validators validator)
        (var-set validator-count (- (var-get validator-count) u1))
        (stx-transfer? 
            (unwrap! (map-get? validator-stakes validator) (err u0))
            validator
            CONTRACT_OWNER)))

;; Public functions
(define-public (register-validator)
    (let ((stake-amount VALIDATOR_STAKE))
        (asserts! (is-eq (var-get current-phase) "none") ERR_NOT_AUTHORIZED)
        (asserts! (<= (var-get validator-count) MAX_VALIDATORS) ERR_TOO_MANY_VALIDATORS)
        (asserts! (>= (stx-get-balance tx-sender) stake-amount) ERR_INVALID_STAKE)
        
        (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
        (map-set validators tx-sender true)
        (map-set validator-stakes tx-sender stake-amount)
        (var-set validator-count (+ (var-get validator-count) u1))
        (ok true)))

(define-public (start-commit-phase)
    (begin
        (asserts! (is-eq (var-get current-phase) "none") ERR_NOT_AUTHORIZED)
        (asserts! (>= (var-get validator-count) MIN_VALIDATORS) ERR_NOT_ENOUGH_VALIDATORS)
        
        (var-set current-phase "commit")
        (var-set phase-start-block block-height)
        (var-set current-request-id (+ (var-get current-request-id) u1))
        (ok true)))

(define-public (submit-commitment (commitment (buff 32)))
    (begin
        (asserts! (is-eq (var-get current-phase) "commit") ERR_COMMIT_PHASE_ENDED)
        (asserts! (map-get? validators tx-sender) ERR_NOT_AUTHORIZED)
        (asserts! 
            (is-none 
                (map-get? commitments 
                    { request-id: (var-get current-request-id), validator: tx-sender }))
            ERR_ALREADY_COMMITTED)
        (asserts! 
            (<= block-height (+ (var-get phase-start-block) COMMIT_WINDOW))
            ERR_COMMIT_PHASE_ENDED)
        
        (map-set commitments
            { request-id: (var-get current-request-id), validator: tx-sender }
            { commitment: commitment, revealed: false, value: none })
        (ok true)))

(define-public (start-reveal-phase)
    (begin
        (asserts! (is-eq (var-get current-phase) "commit") ERR_NOT_AUTHORIZED)
        (asserts! 
            (>= block-height (+ (var-get phase-start-block) COMMIT_WINDOW))
            ERR_COMMIT_PHASE_ENDED)
        
        (var-set current-phase "reveal")
        (var-set phase-start-block block-height)
        (ok true)))

(define-public (reveal-commitment (revealed-value (buff 32)))
    (begin
        (asserts! (is-eq (var-get current-phase) "reveal") ERR_REVEAL_PHASE_ENDED)
        (asserts! 
            (<= block-height (+ (var-get phase-start-block) REVEAL_WINDOW))
            ERR_REVEAL_PHASE_ENDED)
        
        (let ((commitment-data 
            (unwrap! 
                (map-get? commitments 
                    { request-id: (var-get current-request-id), validator: tx-sender })
                ERR_NO_COMMITMENT_FOUND)))
            
            (asserts! 
                (verify-commitment 
                    (get commitment commitment-data)
                    revealed-value
                    tx-sender)
                ERR_INVALID_REVEAL)
            
            (map-set commitments
                { request-id: (var-get current-request-id), validator: tx-sender }
                { commitment: (get commitment commitment-data),
                  revealed: true,
                  value: (some revealed-value) })
            (ok true))))

(define-public (finalize-random-seed)
    (begin
        (asserts! (is-eq (var-get current-phase) "reveal") ERR_NOT_AUTHORIZED)
        (asserts! 
            (>= block-height (+ (var-get phase-start-block) REVEAL_WINDOW))
            ERR_REVEAL_PHASE_ENDED)
        
        (let ((revealed-values 
            (fold combine-revealed-values
                (unwrap-panic 
                    (map-get? commitments 
                        { request-id: (var-get current-request-id), 
                          validator: (var-get current-request-id) }))
                (list))))
            
            (map-set random-seeds (var-get current-request-id) revealed-values)
            (var-set current-phase "none")
            (ok revealed-values))))

(define-read-only (get-random-seed (request-id uint))
    (ok (unwrap! (map-get? random-seeds request-id) ERR_NO_COMMITMENT_FOUND)))

(define-public (withdraw-stake)
    (let ((stake-amount (unwrap! (map-get? validator-stakes tx-sender) ERR_NOT_AUTHORIZED)))
        (asserts! (is-eq (var-get current-phase) "none") ERR_NOT_AUTHORIZED)
        (try! (as-contract (stx-transfer? stake-amount tx-sender tx-sender)))
        (map-delete validator-stakes tx-sender)
        (map-delete validators tx-sender)
        (var-set validator-count (- (var-get validator-count) u1))
        (ok true)))