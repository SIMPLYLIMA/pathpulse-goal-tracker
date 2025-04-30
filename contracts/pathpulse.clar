;; PathPulse Goal Tracker
;; A decentralized personal goal tracking system that allows users to create, manage, and verify progress
;; on their personal goals with optional staking, deadlines, and third-party verification.

;; =======================================
;; Constants and Error Codes
;; =======================================
(define-constant contract-owner tx-sender)

;; Error codes
(define-constant err-not-authorized (err u100))
(define-constant err-no-such-goal (err u101))
(define-constant err-no-such-milestone (err u102))
(define-constant err-goal-already-exists (err u103))
(define-constant err-milestone-already-exists (err u104))
(define-constant err-goal-deadline-passed (err u105))
(define-constant err-goal-completed (err u106))
(define-constant err-insufficient-stake (err u107))
(define-constant err-not-witness (err u108))
(define-constant err-invalid-privacy-setting (err u109))
(define-constant err-invalid-deadline (err u110))
(define-constant err-milestone-already-completed (err u111))
(define-constant err-verification-required (err u112))

;; Privacy settings
(define-constant privacy-public u1)
(define-constant privacy-private u2)

;; =======================================
;; Data Maps and Variables
;; =======================================

;; Maps goal ID to goal details
(define-map goals
  {
    user: principal,
    goal-id: uint
  }
  {
    title: (string-ascii 100),
    description: (string-utf8 500),
    deadline: (optional uint),
    created-at: uint,
    completed-at: (optional uint),
    privacy: uint,
    witness: (optional principal),
    stake-amount: uint,
    total-milestones: uint,
    completed-milestones: uint
  }
)

;; Maps milestone ID to milestone details
(define-map milestones
  {
    user: principal,
    goal-id: uint,
    milestone-id: uint
  }
  {
    title: (string-ascii 100),
    description: (string-utf8 500),
    completed: bool,
    completed-at: (optional uint),
    verified-by: (optional principal)
  }
)

;; Tracks the next goal ID for each user
(define-map user-goal-count principal uint)

;; =======================================
;; Private Functions
;; =======================================

;; Get the next goal ID for a user
(define-private (get-next-goal-id (user principal))
  (default-to u1 (map-get? user-goal-count user))
)

;; Update the goal count for a user
(define-private (update-user-goal-count (user principal))
  (let
    (
      (current-count (get-next-goal-id user))
    )
    (map-set user-goal-count user (+ current-count u1))
    current-count
  )
)

;; Check if user is authorized to modify a goal
(define-private (is-goal-owner (user principal) (goal-id uint))
  (is-eq tx-sender user)
)

;; Check if user is authorized as a witness for a goal
(define-private (is-goal-witness (user principal) (goal-id uint))
  (let
    (
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) false))
      (witness (get witness goal-data))
    )
    (and
      (is-some witness)
      (is-eq tx-sender (unwrap! witness false))
    )
  )
)

;; Validate privacy setting
(define-private (validate-privacy (privacy-setting uint))
  (or 
    (is-eq privacy-setting privacy-public)
    (is-eq privacy-setting privacy-private)
  )
)

;; Update goal completion status
(define-private (update-goal-completion (user principal) (goal-id uint))
  (let
    (
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) err-no-such-goal))
      (total-milestones (get total-milestones goal-data))
      (completed-milestones (get completed-milestones goal-data))
    )
    (if (is-eq total-milestones completed-milestones)
      (map-set goals 
        {user: user, goal-id: goal-id}
        (merge goal-data {completed-at: (some block-height)})
      )
      true
    )
  )
)

;; =======================================
;; Read-Only Functions
;; =======================================

;; Get goal details
(define-read-only (get-goal (user principal) (goal-id uint))
  (let
    (
      (goal-data (map-get? goals {user: user, goal-id: goal-id}))
    )
    (if (is-some goal-data)
      (let
        (
          (unwrapped-data (unwrap-panic goal-data))
          (privacy (get privacy unwrapped-data))
        )
        (if (or 
              (is-eq privacy privacy-public)
              (is-eq tx-sender user)
              (is-eq tx-sender (default-to contract-owner (get witness unwrapped-data)))
            )
          (ok unwrapped-data)
          (err err-not-authorized)
        )
      )
      (err err-no-such-goal)
    )
  )
)

;; Get milestone details
(define-read-only (get-milestone (user principal) (goal-id uint) (milestone-id uint))
  (let
    (
      (goal-data (map-get? goals {user: user, goal-id: goal-id}))
    )
    (if (is-some goal-data)
      (let
        (
          (unwrapped-goal (unwrap-panic goal-data))
          (privacy (get privacy unwrapped-goal))
          (milestone-data (map-get? milestones {user: user, goal-id: goal-id, milestone-id: milestone-id}))
        )
        (if (and
              (is-some milestone-data)
              (or 
                (is-eq privacy privacy-public)
                (is-eq tx-sender user)
                (is-eq tx-sender (default-to contract-owner (get witness unwrapped-goal)))
              )
            )
          (ok (unwrap-panic milestone-data))
          (if (is-none milestone-data)
            (err err-no-such-milestone)
            (err err-not-authorized)
          )
        )
      )
      (err err-no-such-goal)
    )
  )
)

;; Get user's goals (only returns goals the requester has access to)
(define-read-only (get-user-goals (user principal))
  (let
    (
      (goal-count (get-next-goal-id user))
    )
    (filter 
      is-accessible-goal 
      (map 
        (compose-goal-id user) 
        (generate-sequence u1 (- goal-count u1))
      )
    )
  )
)

;; Helper function to compose goal IDs
(define-private (compose-goal-id (user principal) (id uint))
  {user: user, goal-id: id}
)

;; Filter function to check if goal is accessible
(define-private (is-accessible-goal (goal-map {user: principal, goal-id: uint}))
  (let
    (
      (user (get user goal-map))
      (goal-id (get goal-id goal-map))
      (goal-data (map-get? goals {user: user, goal-id: goal-id}))
    )
    (if (is-some goal-data)
      (let
        (
          (unwrapped-data (unwrap-panic goal-data))
          (privacy (get privacy unwrapped-data))
        )
        (or 
          (is-eq privacy privacy-public)
          (is-eq tx-sender user)
          (is-eq tx-sender (default-to contract-owner (get witness unwrapped-data)))
        )
      )
      false
    )
  )
)

;; =======================================
;; Public Functions
;; =======================================

;; Create a new goal
(define-public (create-goal 
    (title (string-ascii 100)) 
    (description (string-utf8 500))
    (deadline (optional uint))
    (privacy uint)
    (witness (optional principal))
    (stake-amount uint)
  )
  (let
    (
      (user tx-sender)
      (goal-id (update-user-goal-count user))
    )
    ;; Validation
    (asserts! (validate-privacy privacy) (err err-invalid-privacy-setting))
    (match deadline deadline-value
      (asserts! (> deadline-value block-height) (err err-invalid-deadline))
      true
    )
    
    ;; Handle staking if amount > 0
    (if (> stake-amount u0)
      (begin
        (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
        (map-set goals
          {user: user, goal-id: goal-id}
          {
            title: title,
            description: description,
            deadline: deadline,
            created-at: block-height,
            completed-at: none,
            privacy: privacy,
            witness: witness,
            stake-amount: stake-amount,
            total-milestones: u0,
            completed-milestones: u0
          }
        )
        (ok goal-id)
      )
      (begin
        (map-set goals
          {user: user, goal-id: goal-id}
          {
            title: title,
            description: description,
            deadline: deadline,
            created-at: block-height,
            completed-at: none,
            privacy: privacy,
            witness: witness,
            stake-amount: u0,
            total-milestones: u0,
            completed-milestones: u0
          }
        )
        (ok goal-id)
      )
    )
  )
)

;; Add milestone to a goal
(define-public (add-milestone
    (goal-id uint)
    (title (string-ascii 100))
    (description (string-utf8 500))
  )
  (let
    (
      (user tx-sender)
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) (err err-no-such-goal)))
      (total-milestones (get total-milestones goal-data))
      (completed-at (get completed-at goal-data))
      (milestone-id (+ total-milestones u1))
    )
    ;; Validate
    (asserts! (is-goal-owner user goal-id) (err err-not-authorized))
    (asserts! (is-none completed-at) (err err-goal-completed))
    
    ;; Check deadline
    (match (get deadline goal-data) deadline-value
      (asserts! (> deadline-value block-height) (err err-goal-deadline-passed))
      true
    )
    
    ;; Create milestone
    (map-set milestones
      {user: user, goal-id: goal-id, milestone-id: milestone-id}
      {
        title: title,
        description: description,
        completed: false,
        completed-at: none,
        verified-by: none
      }
    )
    
    ;; Update goal with new milestone count
    (map-set goals
      {user: user, goal-id: goal-id}
      (merge goal-data {total-milestones: milestone-id})
    )
    
    (ok milestone-id)
  )
)

;; Complete a milestone
(define-public (complete-milestone (goal-id uint) (milestone-id uint))
  (let
    (
      (user tx-sender)
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) (err err-no-such-goal)))
      (milestone-data (unwrap! (map-get? milestones {user: user, goal-id: goal-id, milestone-id: milestone-id}) (err err-no-such-milestone)))
      (completed-at (get completed-at goal-data))
      (witness (get witness goal-data))
      (completed (get completed milestone-data))
    )
    ;; Validate
    (asserts! (is-goal-owner user goal-id) (err err-not-authorized))
    (asserts! (is-none completed-at) (err err-goal-completed))
    (asserts! (not completed) (err err-milestone-already-completed))
    
    ;; Check deadline
    (match (get deadline goal-data) deadline-value
      (asserts! (> deadline-value block-height) (err err-goal-deadline-passed))
      true
    )
    
    ;; Update milestone
    (if (is-some witness)
      ;; If there's a witness, mark as pending verification
      (map-set milestones
        {user: user, goal-id: goal-id, milestone-id: milestone-id}
        (merge milestone-data {
          completed: true,
          completed-at: (some block-height)
        })
      )
      ;; Otherwise, mark as completed
      (begin
        (map-set milestones
          {user: user, goal-id: goal-id, milestone-id: milestone-id}
          (merge milestone-data {
            completed: true,
            completed-at: (some block-height),
            verified-by: (some user)
          })
        )
        ;; Update completed milestone count
        (map-set goals
          {user: user, goal-id: goal-id}
          (merge goal-data {
            completed-milestones: (+ (get completed-milestones goal-data) u1)
          })
        )
        ;; Check if goal is now complete
        (try! (as-bool (update-goal-completion user goal-id)))
      )
    )
    
    (ok true)
  )
)

;; Verify a milestone (for witnesses)
(define-public (verify-milestone (user principal) (goal-id uint) (milestone-id uint))
  (let
    (
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) (err err-no-such-goal)))
      (milestone-data (unwrap! (map-get? milestones {user: user, goal-id: goal-id, milestone-id: milestone-id}) (err err-no-such-milestone)))
      (witness (get witness goal-data))
      (is-witness (is-goal-witness user goal-id))
      (completed (get completed milestone-data))
      (verified-by (get verified-by milestone-data))
    )
    ;; Validate
    (asserts! is-witness (err err-not-witness))
    (asserts! completed (err err-milestone-already-completed))
    (asserts! (is-none verified-by) (err err-milestone-already-completed))
    
    ;; Update milestone
    (map-set milestones
      {user: user, goal-id: goal-id, milestone-id: milestone-id}
      (merge milestone-data {
        verified-by: (some tx-sender)
      })
    )
    
    ;; Update completed milestone count
    (map-set goals
      {user: user, goal-id: goal-id}
      (merge goal-data {
        completed-milestones: (+ (get completed-milestones goal-data) u1)
      })
    )
    
    ;; Check if goal is now complete
    (try! (as-bool (update-goal-completion user goal-id)))
    
    (ok true)
  )
)

;; Claim staked funds upon goal completion
(define-public (claim-stake (goal-id uint))
  (let
    (
      (user tx-sender)
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) (err err-no-such-goal)))
      (completed-at (get completed-at goal-data))
      (stake-amount (get stake-amount goal-data))
    )
    ;; Validate
    (asserts! (is-goal-owner user goal-id) (err err-not-authorized))
    (asserts! (is-some completed-at) (err err-goal-completed))
    (asserts! (> stake-amount u0) (err err-insufficient-stake))
    
    ;; Transfer stake back to user
    (try! (as-contract (stx-transfer? stake-amount tx-sender user)))
    
    ;; Update goal to show stake has been claimed
    (map-set goals
      {user: user, goal-id: goal-id}
      (merge goal-data {stake-amount: u0})
    )
    
    (ok true)
  )
)

;; Update goal privacy setting
(define-public (update-goal-privacy (goal-id uint) (privacy uint))
  (let
    (
      (user tx-sender)
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) (err err-no-such-goal)))
    )
    ;; Validate
    (asserts! (is-goal-owner user goal-id) (err err-not-authorized))
    (asserts! (validate-privacy privacy) (err err-invalid-privacy-setting))
    
    ;; Update privacy setting
    (map-set goals
      {user: user, goal-id: goal-id}
      (merge goal-data {privacy: privacy})
    )
    
    (ok true)
  )
)

;; Add or change witness for a goal
(define-public (update-goal-witness (goal-id uint) (witness (optional principal)))
  (let
    (
      (user tx-sender)
      (goal-data (unwrap! (map-get? goals {user: user, goal-id: goal-id}) (err err-no-such-goal)))
      (completed-at (get completed-at goal-data))
    )
    ;; Validate
    (asserts! (is-goal-owner user goal-id) (err err-not-authorized))
    (asserts! (is-none completed-at) (err err-goal-completed))
    
    ;; Update witness
    (map-set goals
      {user: user, goal-id: goal-id}
      (merge goal-data {witness: witness})
    )
    
    (ok true)
  )
)