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
(define-constant ERR-CLUSTER-FULL (err u113))
(define-constant ERR-PROOF-NOT-ACTIVE (err u114))

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant MINIMUM-STAKE u1000000) ;; 1 STX in microSTX
(define-constant VERIFICATION-PERIOD u144) ;; ~24 hours in blocks
(define-constant TEMPORAL-THRESHOLD u100)
(define-constant MAX-CLUSTER-SIZE u8)
(define-constant MIN-PROOF-DURATION u10) ;; Minimum 10 blocks
(define-constant MAX-PROOF-DURATION u10080) ;; Maximum ~7 days in blocks

;; Data Variables
(define-data-var next-timechain-id uint u1)
(define-data-var next-proof-id uint u1)
(define-data-var next-certificate-id uint u1)
(define-data-var next-cluster-id uint u1)
(define-data-var temporal-fee uint u50) ;; 0.5%
(define-data-var total-temporal-weight uint u0)
(define-data-var active-epoch-id uint u0)
(define-data-var contract-paused bool false)

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
        joined-at: uint,
        last-activity: uint
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
        expiry: (optional uint),
        verifier: (optional principal)
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
        leader: principal,
        status: (string-ascii 16)
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
        winner: (optional principal),
        created-at: uint
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
        required-attestations: uint,
        created-at: uint
    })

(define-map temporal-epochs
    { epoch-id: uint }
    {
        name: (string-ascii 64),
        start-block: uint,
        end-block: uint,
        total-prize-pool: uint,
        active-proofs: (list 10 uint),
        participants: uint,
        status: (string-ascii 16)
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
        active: bool,
        created-at: uint
    })

;; Emergency Functions
(define-public (pause-contract)
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (var-set contract-paused true)
        (ok true)))

(define-public (unpause-contract)
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (var-set contract-paused false)
        (ok true)))

;; Owner/Admin Functions
(define-public (create-temporal-chain (name (string-ascii 64)) (location (string-ascii 128)) (sequence-type (string-ascii 64)) (validation-threshold uint))
    (let ((timechain-id (var-get next-timechain-id)))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> (len name) u0) ERR-INVALID-INPUT)
        (asserts! (> validation-threshold u0) ERR-INVALID-INPUT)
        (asserts! (<= validation-threshold u100) ERR-INVALID-INPUT)
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

(define-public (deactivate-temporal-chain (timechain-id uint))
    (let ((timechain (map-get? temporal-chains { timechain-id: timechain-id })))
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (is-some timechain) ERR-NOT-FOUND)
        (map-set temporal-chains
            { timechain-id: timechain-id }
            (merge (unwrap-panic timechain) { active: false }))
        (ok true)))

(define-public (activate-temporal-epoch (name (string-ascii 64)) (duration uint) (prize-pool uint))
    (let ((epoch-id (+ (var-get active-epoch-id) u1)))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> duration u0) ERR-INVALID-INPUT)
        (asserts! (> prize-pool u0) ERR-INVALID-INPUT)
        (asserts! (> (len name) u0) ERR-INVALID-INPUT)
        (map-set temporal-epochs
            { epoch-id: epoch-id }
            {
                name: name,
                start-block: block-height,
                end-block: (+ block-height duration),
                total-prize-pool: prize-pool,
                active-proofs: (list),
                participants: u0,
                status: "active"
            })
        (var-set active-epoch-id epoch-id)
        (ok epoch-id)))

(define-public (register-algorithm-category (category (string-ascii 32)) (weight-multiplier uint) (required-attestations uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> (len category) u0) ERR-INVALID-INPUT)
        (asserts! (> weight-multiplier u0) ERR-INVALID-INPUT)
        (asserts! (<= weight-multiplier u1000) ERR-INVALID-INPUT) ;; Max 10x multiplier
        (map-set algorithm-categories
            { category: category }
            {
                active: true,
                weight-multiplier: weight-multiplier,
                required-attestations: required-attestations,
                created-at: block-height
            })
        (ok true)))

(define-public (create-timelock-class (class-name (string-ascii 64)) (required-algorithms (list 5 (string-ascii 32))) (min-temporal-weight uint) (cascade-requirement uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (> (len class-name) u0) ERR-INVALID-INPUT)
        (asserts! (> min-temporal-weight u0) ERR-INVALID-INPUT)
        (asserts! (> (len required-algorithms) u0) ERR-INVALID-INPUT)
        (map-set timelock-classes
            { class-name: class-name }
            {
                required-algorithms: required-algorithms,
                min-temporal-weight: min-temporal-weight,
                cascade-requirement: cascade-requirement,
                active: true,
                created-at: block-height
            })
        (ok true)))

;; Public Functions
(define-public (register-validator (algorithms (list 10 (string-ascii 32))))
    (let ((existing-profile (map-get? validator-profiles { validator: tx-sender })))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
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
                joined-at: block-height,
                last-activity: block-height
            })
        (ok true)))

(define-public (update-validator-activity)
    (let ((profile (map-get? validator-profiles { validator: tx-sender })))
        (asserts! (is-some profile) ERR-NOT-FOUND)
        (map-set validator-profiles
            { validator: tx-sender }
            (merge (unwrap-panic profile) { last-activity: block-height }))
        (ok true)))

(define-public (create-temporal-proof (title (string-ascii 128)) (description (string-ascii 512)) (timechain-id uint) (required-algorithms (list 5 (string-ascii 32))) (reward-amount uint) (duration uint))
    (let ((proof-id (var-get next-proof-id))
          (timechain (map-get? temporal-chains { timechain-id: timechain-id })))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
        (asserts! (is-some timechain) ERR-NOT-FOUND)
        (asserts! (get active (unwrap-panic timechain)) ERR-INACTIVE-TIMECHAIN)
        (asserts! (> (len title) u0) ERR-INVALID-INPUT)
        (asserts! (> reward-amount u0) ERR-INVALID-INPUT)
        (asserts! (>= duration MIN-PROOF-DURATION) ERR-INVALID-INPUT)
        (asserts! (<= duration MAX-PROOF-DURATION) ERR-INVALID-INPUT)
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
                winner: none,
                created-at: block-height
            })
        (var-set next-proof-id (+ proof-id u1))
        (ok proof-id)))

(define-public (join-temporal-proof (proof-id uint))
    (let ((proof (map-get? temporal-proofs { proof-id: proof-id }))
          (profile (map-get? validator-profiles { validator: tx-sender })))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
        (asserts! (is-some proof) ERR-NOT-FOUND)
        (asserts! (is-some profile) ERR-NOT-FOUND)
        (asserts! (is-eq (get status (unwrap-panic proof)) "active") ERR-PROOF-NOT-ACTIVE)
        (asserts! (< block-height (get deadline (unwrap-panic proof))) ERR-PROOF-EXPIRED)
        (asserts! (>= (stx-get-balance tx-sender) MINIMUM-STAKE) ERR-INSUFFICIENT-BALANCE)
        (asserts! (< (len (get participants (unwrap-panic proof))) u20) ERR-CLUSTER-FULL)
        
        ;; Check if already a participant
        (asserts! (is-none (index-of (get participants (unwrap-panic proof)) tx-sender)) ERR-ALREADY-EXISTS)
        
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
        
        ;; Update validator activity
        (try! (update-validator-activity))
        (ok true)))

(define-public (create-validator-cluster (name (string-ascii 64)) (members (list 8 principal)))
    (let ((cluster-id (var-get next-cluster-id)))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
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
                leader: tx-sender,
                status: "active"
            })
        (var-set next-cluster-id (+ cluster-id u1))
        (ok cluster-id)))

(define-public (submit-attestation (attestation-id (string-ascii 64)) (proof-id uint) (temporal-rating uint) (feedback (string-ascii 256)))
    (let ((proof (map-get? temporal-proofs { proof-id: proof-id })))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
        (asserts! (is-some proof) ERR-NOT-FOUND)
        (asserts! (<= temporal-rating u100) ERR-INVALID-INPUT)
        (asserts! (> temporal-rating u0) ERR-INVALID-INPUT)
        (asserts! (> (len attestation-id) u0) ERR-INVALID-INPUT)
        ;; Check if attestation already exists
        (asserts! (is-none (map-get? validator-attestations { attestation-id: attestation-id })) ERR-ALREADY-EXISTS)
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
        (try! (update-validator-activity))
        (ok true)))

(define-public (mint-temporal-certificate (certificate-type (string-ascii 32)) (timechain-id uint) (temporal-value uint) (metadata (string-ascii 256)))
    (let ((certificate-id (var-get next-certificate-id))
          (profile (map-get? validator-profiles { validator: tx-sender })))
        (asserts! (not (var-get contract-paused)) ERR-NOT-AUTHORIZED)
        (asserts! (is-some profile) ERR-NOT-FOUND)
        (asserts! (>= (get temporal-weight (unwrap-panic profile)) TEMPORAL-THRESHOLD) ERR-TEMPORAL-THRESHOLD-NOT-MET)
        (asserts! (> temporal-value u0) ERR-INVALID-INPUT)
        (asserts! (> (len certificate-type) u0) ERR-INVALID-INPUT)
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
                expiry: none,
                verifier: none
            })
        (var-set next-certificate-id (+ certificate-id u1))
        (ok certificate-id)))

(define-public (complete-temporal-proof (proof-id uint) (winner principal))
    (let ((proof (map-get? temporal-proofs { proof-id: proof-id })))
        (asserts! (is-some proof) ERR-NOT-FOUND)
        (asserts! (is-eq tx-sender (get sponsor (unwrap-panic proof))) ERR-NOT-AUTHORIZED)
        (asserts! (is-eq (get status (unwrap-panic proof)) "active") ERR-PROOF-NOT-ACTIVE)
        ;; Check if winner is a participant
        (asserts! (is-some (index-of (get participants (unwrap-panic proof)) winner)) ERR-NOT-FOUND)
        
        ;; Update proof status and winner
        (map-set temporal-proofs
            { proof-id: proof-id }
            (merge (unwrap-panic proof) 
                   { status: "completed", winner: (some winner) }))
        
        ;; Transfer reward to winner
        (try! (as-contract (stx-transfer? (get reward-amount (unwrap-panic proof)) tx-sender winner)))
        
        ;; Update winner's profile
        (let ((winner-profile (unwrap-panic (map-get? validator-profiles { validator: winner }))))
            (map-set validator-profiles
                { validator: winner }
                (merge winner-profile 
                       { temporal-weight: (+ (get temporal-weight winner-profile) u50),
                         verified-timestamps: (+ (get verified-timestamps winner-profile) u1),
                         reputation: (+ (get reputation winner-profile) u10),
                         last-activity: block-height })))
        (ok true)))

(define-public (update-validator-weight (validator principal) (new-weight uint))
    (let ((profile (map-get? validator-profiles { validator: validator })))
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (is-some profile) ERR-NOT-FOUND)
        (asserts! (<= new-weight u10000) ERR-INVALID-INPUT) ;; Max weight limit
        (map-set validator-profiles
            { validator: validator }
            (merge (unwrap-panic profile) 
                   { temporal-weight: new-weight }))
        (ok true)))

(define-public (verify-certificate (certificate-id uint))
    (let ((certificate (map-get? temporal-certificates { certificate-id: certificate-id })))
        (asserts! (is-some certificate) ERR-NOT-FOUND)
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (asserts! (not (get verified (unwrap-panic certificate))) ERR-ALREADY-VERIFIED)
        (map-set temporal-certificates
            { certificate-id: certificate-id }
            (merge (unwrap-panic certificate) 
                   { verified: true, verifier: (some tx-sender) }))
        (ok true)))

(define-public (release-validator-stake (validator principal) (proof-id uint))
    (let ((stake (map-get? validator-stakes { validator: validator, proof-id: proof-id })))
        (asserts! (is-some stake) ERR-NOT-FOUND)
        (asserts! (not (get released (unwrap-panic stake))) ERR-ALREADY-EXISTS)
        (asserts! (> (- block-height (get locked-at (unwrap-panic stake))) VERIFICATION-PERIOD) ERR-INVALID-TIMESTAMP)
        
        ;; Release the stake
        (try! (as-contract (stx-transfer? (get amount (unwrap-panic stake)) tx-sender validator)))
        (map-set validator-stakes
            { validator: validator, proof-id: proof-id }
            (merge (unwrap-panic stake) 
                   { released: true }))
        (ok true)))

;; Read-only Functions
(define-read-only (get-temporal-chain (timechain-id uint))
    (map-get? temporal-chains { timechain-id: timechain-id }))

(define-read-only (get-validator-profile (validator principal))
    (map-get? validator-profiles { validator: validator }))

(define-read-only (get-temporal-proof (proof-id uint))
    (map-get? temporal-proofs { proof-id: proof-id }))

(define-read-only (get-certificate (certificate-id uint))
    (map-get? temporal-certificates { certificate-id: certificate-id }))

(define-read-only (get-validator-cluster (cluster-id uint))
    (map-get? validator-clusters { cluster-id: cluster-id }))

(define-read-only (get-attestation (attestation-id (string-ascii 64)))
    (map-get? validator-attestations { attestation-id: attestation-id }))

(define-read-only (get-algorithm-category (category (string-ascii 32)))
    (map-get? algorithm-categories { category: category }))

(define-read-only (get-temporal-epoch (epoch-id uint))
    (map-get? temporal-epochs { epoch-id: epoch-id }))

(define-read-only (get-validator-stake (validator principal) (proof-id uint))
    (map-get? validator-stakes { validator: validator, proof-id: proof-id }))

(define-read-only (get-timelock-class (class-name (string-ascii 64)))
    (map-get? timelock-classes { class-name: class-name }))

(define-read-only (get-current-epoch)
    (var-get active-epoch-id))

(define-read-only (get-total-temporal-weight)
    (var-get total-temporal-weight))

(define-read-only (is-contract-paused)
    (var-get contract-paused))

(define-read-only (get-next-ids)
    {
        timechain: (var-get next-timechain-id),
        proof: (var-get next-proof-id),
        certificate: (var-get next-certificate-id),
        cluster: (var-get next-cluster-id)
    })

(define-read-only (is-validator-registered (validator principal))
    (is-some (map-get? validator-profiles { validator: validator })))

(define-read-only (get-proof-participants (proof-id uint))
    (match (map-get? temporal-proofs { proof-id: proof-id })
        proof (some (get participants proof))
        none))