;; ValeMint - Decentralized Temporal Verification Infrastructure
;; Comprehensive Smart Contract for Cryptographic Timestamp Proofs and Validator Networks

;; Error Constants
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-EXISTS (err u101))
(define-constant ERR-NOT-FOUND (err u102))
(define-constant ERR-INSUFFICIENT-BALANCE (err u103))
(define-constant ERR-INVALID-INPUT (err u104))
(define-constant ERR-INACTIVE-TIMECHAIN (err u105))
(define-constant ERR-INVALID-TIMESTAMP (err u106))
(define-constant ERR-PROOF-EXPIRED (err u107))
(define-constant ERR-ALREADY-VERIFIED (err u108))
(define-constant ERR-INSUFFICIENT-STAKE (err u109))
(define-constant ERR-INVALID-SEQUENCE (err u110))
(define-constant ERR-VALIDATOR-REJECTION (err u111))
(define-constant ERR-TEMPORAL-THRESHOLD-NOT-MET (err u112))

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MINIMUM-STAKE u1000000) ;; 1 STX in microSTX
(define-constant VERIFICATION-PERIOD u144) ;; ~24 hours in blocks
(define-constant TEMPORAL-THRESHOLD u100)
(define-constant MAX-CLUSTER-SIZE u8)

;; Data Variables
(define-data-var next-timechain-id uint u1)
(define-data-var next-proof-id uint u1)
(define-data-var next-certificate-id uint u1)
(define-data-var next-cluster-id uint u1)
(define-data-var temporal-fee uint u50) ;; 0.5%
(define-data-var total-temporal-weight uint u0)
(define-data-var active-epoch-id uint u0)

;; Data Maps
(define-map temporal-chains
    { timechain-id: uint }
    { 
        name: (string-ascii 64),
        location: (string-ascii 128),
        sequence-type: (string-ascii 64),
        active: bool,
        total-weight: uint,
        validation-threshold: uint,
        creator: principal,
        created-at: uint
    })

(define-map validator-profiles
    { validator: principal }
    {
        algorithms: (list 10 (string-ascii 32)),
        temporal-weight: uint,
        verified-timestamps: uint,
        cascade-level: uint,
        staked-tokens: uint,
        active-clusters: (list 5 uint),
        reputation: uint,
        joined-at: uint
    })

(define-map temporal-certificates
    { certificate-id: uint }
    {
        owner: principal,
        certificate-type: (string-ascii 32),
        timechain-id: uint,
        temporal-value: uint,
        metadata: (string-ascii 256),
        verified: bool,
        created-at: uint,
        expiry: (optional uint)
    })

(define-map validator-clusters
    { cluster-id: uint }
    {
        name: (string-ascii 64),
        members: (list 8 principal),
        active-proof: (optional uint),
        total-weight: uint,
        cascade-score: uint,
        created-at: uint,
        leader: principal
    })

(define-map temporal-proofs
    { proof-id: uint }
    {
        title: (string-ascii 128),
        description: (string-ascii 512),
        sponsor: principal,
        timechain-id: uint,
        required-algorithms: (list 5 (string-ascii 32)),
        reward-amount: uint,
        participants: (list 20 principal),
        deadline: uint,
        status: (string-ascii 16),
        winner: (optional principal)
    })

(define-map validator-attestations
    { attestation-id: (string-ascii 64) }
    {
        validator: principal,
        network-verifier: principal,
        proof-id: uint,
        verified: bool,
        temporal-rating: uint,
        feedback: (string-ascii 256),
        timestamp: uint
    })

(define-map algorithm-categories
    { category: (string-ascii 32) }
    {
        active: bool,
        weight-multiplier: uint,
        required-attestations: uint
    })

(define-map temporal-epochs
    { epoch-id: uint }
    {
        name: (string-ascii 64),
        start-block: uint,
        end-block: uint,
        total-prize-pool: uint,
        active-proofs: (list 10 uint),
        participants: uint
    })

(define-map validator-stakes
    { validator: principal, proof-id: uint }
    {
        amount: uint,
        locked-at: uint,
        released: bool
    })

(define-map timelock-classes
    { class-name: (string-ascii 64) }
    {
        required-algorithms: (list 5 (string-ascii 32)),
        min-temporal-weight: uint,
        cascade-requirement: uint,
        active: bool
    })

;; Owner/Admin Functions
(define-public (create-temporal-chain (name (string-ascii 64)) (location (string-ascii 128)) (sequence-type (string-ascii 64)) (validation-threshold uint))
    (let ((timechain-id (var-get next-timechain-id)))
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> (len name) u0) ERR-INVALID-INPUT)
        (asserts! (> validation-threshold u0) ERR-INVALID-INPUT)
        (map-set temporal-chains 
            { timechain-id: timechain-id }
            {
                name: name,
                location: location,
                sequence-type: sequence-type,
                active: true,
                total-weight: u0,
                validation-threshold: validation-threshold,
                creator: tx-sender,
                created-at: block-height
            })
        (var-set next-timechain-id (+ timechain-id u1))
        (ok timechain-id)))

(define-public (activate-temporal-epoch (name (string-ascii 64)) (duration uint) (prize-pool uint))
    (let ((epoch-id (+ (var-get active-epoch-id) u1)))
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> duration u0) ERR-INVALID-INPUT)
        (asserts! (> prize-pool u0) ERR-INVALID-INPUT)
        (map-set temporal-epochs
            { epoch-id: epoch-id }
            {
                name: name,
                start-block: block-height,
                end-block: (+ block-height duration),
                total-prize-pool: prize-pool,
                active-proofs: (list),
                participants: u0
            })
        (var-set active-epoch-id epoch-id)
        (ok epoch-id)))

(define-public (register-algorithm-category (category (string-ascii 32)) (weight-multiplier uint) (required-attestations uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> (len category) u0) ERR-INVALID-INPUT)
        (asserts! (> weight-multiplier u0) ERR-INVALID-INPUT)
        (map-set algorithm-categories
            { category: category }
            {
                active: true,
                weight-multiplier: weight-multiplier,
                required-attestations: required-attestations
            })
        (ok true)))

(define-public (create-timelock-class (class-name (string-ascii 64)) (required-algorithms (list 5 (string-ascii 32))) (min-temporal-weight uint) (cascade-requirement uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> (len class-name) u0) ERR-INVALID-INPUT)
        (asserts! (> min-temporal-weight u0) ERR-INVALID-INPUT)
        (map-set timelock-classes
            { class-name: class-name }
            {
                required-algorithms: required-algorithms,
                min-temporal-weight: min-temporal-weight,
                cascade-requirement: cascade-requirement,
                active: true
            })
        (ok true)))

;; Public Functions
(define-public (register-validator (algorithms (list 10 (string-ascii 32))))
    (let ((existing-profile (map-get? validator-profiles { validator: tx-sender })))
        (asserts! (is-none existing-profile) ERR-ALREADY-EXISTS)
        (asserts! (> (len algorithms) u0) ERR-INVALID-INPUT)
        (map-set validator-profiles
            { validator: tx-sender }
            {
                algorithms: algorithms,
                temporal-weight: u0,
                verified-timestamps: u0,
                cascade-level: u0,
                staked-tokens: u0,
                active-clusters: (list),
                reputation: u100,
                joined-at: block-height
            })
        (ok true)))

(define-public (create-temporal-proof (title (string-ascii 128)) (description (string-ascii 512)) (timechain-id uint) (required-algorithms (list 5 (string-ascii 32))) (reward-amount uint) (duration uint))
    (let ((proof-id (var-get next-proof-id))
          (timechain (map-get? temporal-chains { timechain-id: timechain-id })))
        (asserts! (is-some timechain) ERR-NOT-FOUND)
        (asserts! (get active (unwrap-panic timechain)) ERR-INACTIVE-TIMECHAIN)
        (asserts! (> (len title) u0) ERR-INVALID-INPUT)
        (asserts! (> reward-amount u0) ERR-INVALID-INPUT)
        (asserts! (> duration u0) ERR-INVALID-INPUT)
        (try! (stx-transfer? reward-amount tx-sender (as-contract tx-sender)))
        (map-set temporal-proofs
            { proof-id: proof-id }
            {
                title: title,
                description: description,
                sponsor: tx-sender,
                timechain-id: timechain-id,
                required-algorithms: required-algorithms,
                reward-amount: reward-amount,
                participants: (list),
                deadline: (+ block-height duration),
                status: "active",
                winner: none
            })
        (var-set next-proof-id (+ proof-id u1))
        (ok proof-id)))

(define-public (join-temporal-proof (proof-id uint))
    (let ((proof (map-get? temporal-proofs { proof-id: proof-id }))
          (profile (map-get? validator-profiles { validator: tx-sender })))
        (asserts! (is-some proof) ERR-NOT-FOUND)
        (asserts! (is-some profile) ERR-NOT-FOUND)
        (asserts! (< block-height (get deadline (unwrap-panic proof))) ERR-PROOF-EXPIRED)
        (asserts! (>= (stx-get-balance tx-sender) MINIMUM-STAKE) ERR-INSUFFICIENT-BALANCE)
        (try! (stx-transfer? MINIMUM-STAKE tx-sender (as-contract tx-sender)))
        (map-set validator-stakes
            { validator: tx-sender, proof-id: proof-id }
            {
                amount: MINIMUM-STAKE,
                locked-at: block-height,
                released: false
            })
        ;; Add participant to proof
        (let ((updated-proof (merge (unwrap-panic proof) 
                                      { participants: (unwrap-panic (as-max-len? (append (get participants (unwrap-panic proof)) tx-sender) u20)) })))
            (map-set temporal-proofs { proof-id: proof-id } updated-proof))
        (ok true)))

(define-public (create-validator-cluster (name (string-ascii 64)) (members (list 8 principal)))
    (let ((cluster-id (var-get next-cluster-id)))
        (asserts! (> (len name) u0) ERR-INVALID-INPUT)
        (asserts! (> (len members) u0) ERR-INVALID-INPUT)
        (asserts! (<= (len members) MAX-CLUSTER-SIZE) ERR-INVALID-INPUT)
        (map-set validator-clusters
            { cluster-id: cluster-id }
            {
                name: name,
                members: members,
                active-proof: none,
                total-weight: u0,
                cascade-score: u0,
                created-at: block-height,
                leader: tx-sender
            })
        (var-set next-cluster-id (+ cluster-id u1))
        (ok cluster-id)))

(define-public (submit-attestation (attestation-id (string-ascii 64)) (proof-id uint) (temporal-rating uint) (feedback (string-ascii 256)))
    (let ((proof (map-get? temporal-proofs { proof-id: proof-id })))
        (asserts! (is-some proof) ERR-NOT-FOUND)
        (asserts! (<= temporal-rating u100) ERR-INVALID-INPUT)
        (asserts! (> temporal-rating u0) ERR-INVALID-INPUT)
        (map-set validator-attestations
            { attestation-id: attestation-id }
            {
                validator: tx-sender,
                network-verifier: tx-sender,
                proof-id: proof-id,
                verified: false,
                temporal-rating: temporal-rating,
                feedback: feedback,
                timestamp: block-height
            })
        (ok true)))

(define-public (mint-temporal-certificate (certificate-type (string-ascii 32)) (timechain-id uint) (temporal-value uint) (metadata (string-ascii 256)))
    (let ((certificate-id (var-get next-certificate-id))
          (profile (map-get? validator-profiles { validator: tx-sender })))
        (asserts! (is-some profile) ERR-NOT-FOUND)
        (asserts! (>= (get temporal-weight (unwrap-panic profile)) TEMPORAL-THRESHOLD) ERR-TEMPORAL-THRESHOLD-NOT-MET)
        (asserts! (> temporal-value u0) ERR-INVALID-INPUT)
        (map-set temporal-certificates
            { certificate-id: certificate-id }
            {
                owner: tx-sender,
                certificate-type: certificate-type,
                timechain-id: timechain-id,
                temporal-value: temporal-value,
                metadata: metadata,
                verified: false,
                created-at: block-height,
                expiry: none
            })
        (var-set next-certificate-id (+ certificate-id u1))
        (ok certificate-id)))

(define-public (complete-temporal-proof (proof-id uint) (winner principal))
    (let ((proof (map-get? temporal-proofs { proof-id: proof-id })))
        (asserts! (is-some proof) ERR-NOT-FOUND)
        (asserts! (is-eq tx-sender (get sponsor (unwrap-panic proof))) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status (unwrap-panic proof)) "active") ERR-INVALID-INPUT)
        
        ;; Update proof status and winner
        (map-set temporal-proofs
            { proof-id: proof