/-!
An executable, deliberately abstract model of the four protocol equations in
kex-03-spec.pdf, Section 3.1.  Cryptographic objects are replaced by concrete
integer terms whose relevant correctness equations are definitional.  This
models protocol wiring and state, not cryptographic security.
-/

namespace CreTAKE

abbrev Pub := Nat
abbrev Sec := Nat
abbrev Ciphertext := Nat
abbrev Key := Nat
abbrev Randomness := Nat
abbrev Sig := Nat
abbrev Comp := Nat

def H (xs : List Comp) : Key :=
  xs.foldl (fun acc x => acc * 31 + x + 1) 17

def G (sk er : Nat) : Randomness :=
  H [sk, er]

/-! Deliberately simple abstract implementations.  The only properties used by
the agreement proofs are the inherited KEM correctness equations. -/

def wGen (r : Randomness) : Pub × Sec := (r, r)
def wEncaps (pk : Pub) : Ciphertext × Key := (pk + 1, pk + 2)
def wDecaps (sk : Sec) (_c : Ciphertext) : Key := sk + 2

def kemGen (i : Nat) : Pub × Sec := (i, i)
def kemEncaps (pk : Pub) : Ciphertext × Key := (pk + 3, pk + 4)
def kemDecaps (sk : Sec) (_c : Ciphertext) : Key := sk + 4

/-! Exact key component read by the successful straightforward branch of
PolarLAC CCA Figure 6.  Encapsulation assigns `(seed,K)` and returns the second
component; decapsulation assigns `(K,seed)` and returns the first component. -/
def polarEncKey (_seed k : Key) : Key := k
def polarDecKey (seed _k : Key) : Key := seed

theorem polar_cca_honest_key_swap
    (seed k : Key) (h : seed ≠ k) :
    polarEncKey seed k ≠ polarDecKey seed k := by
  simp only [polarEncKey, polarDecKey]
  exact fun hk => h hk.symm

def twoGen1 (i : Nat) : Pub × Sec := (i, i)
def twoGen2 (r : Randomness) : Pub × Sec := (r, r)
def twoEncaps (pk₁ pk₂ : Pub) : Ciphertext × Key :=
  (pk₁ + pk₂ + 5, pk₁ + pk₂ + 6)
def twoDecaps (sk₁ sk₂ : Sec) (_c : Ciphertext) : Key := sk₁ + sk₂ + 6

def sign (sk : Sec) (m : List Comp) : Sig := sk + H m
def verify (pk : Pub) (m : List Comp) (σ : Sig) : Bool :=
  σ == pk + H m

/-! K2S: initiator has the long-term KEM key; responder has the signature key.
Messages are already parsed into their exact component structures. -/

structure K2SResp where
  ec : Ciphertext
  ci : Ciphertext
  sigma : Sig
  deriving Repr, DecidableEq

structure K2SState where
  fsk : Sec
  epk : Pub
  deriving Repr, DecidableEq

def k2sInit (r : Randomness) : Pub × K2SState :=
  let e := wGen r
  (e.1, { fsk := e.2, epk := e.1 })

def k2sResp (i j : Nat) (epk : Pub) : K2SResp × Key :=
  let ec := wEncaps epk
  let ci := kemEncaps i
  let σ := sign j [epk, ec.1, ci.1]
  ({ ec := ec.1, ci := ci.1, sigma := σ },
   H [i, j, epk, ec.1, ci.1, ci.2, ec.2])

def k2sFinal (i j : Nat) (st : K2SState) (resp : K2SResp) : Option Key :=
  if verify j [st.epk, resp.ec, resp.ci] resp.sigma then
    let ek := wDecaps st.fsk resp.ec
    let ki := kemDecaps i resp.ci
    some (H [i, j, st.epk, resp.ec, resp.ci, ki, ek])
  else
    none

theorem k2s_honest_agreement (i j r : Randomness) :
    k2sFinal i j (k2sInit r).2 (k2sResp i j (wGen r).1).1 =
      some (k2sResp i j (wGen r).1).2 := by
  simp [k2sFinal, k2sInit, k2sResp, wGen, wEncaps, wDecaps,
        kemEncaps, kemDecaps, verify, sign]

theorem k2s_wrong_partner_rejected (i j r : Randomness) :
    k2sFinal i (j + 1) (k2sInit r).2 (k2sResp i j (wGen r).1).1 = none := by
  simp [k2sFinal, k2sInit, k2sResp, wGen, verify, sign]

/-! S2K: initiator has the signature key; responder has the KEM key. -/

structure S2KInitMsg where
  epk : Pub
  cj : Ciphertext
  sigma : Sig
  deriving Repr, DecidableEq

structure S2KState where
  er : Randomness
  cj : Ciphertext
  kj : Key
  deriving Repr, DecidableEq

def s2kInit (i j er : Randomness) : S2KInitMsg × S2KState :=
  let e := wGen (G i er)
  let cj := kemEncaps j
  ({ epk := e.1, cj := cj.1, sigma := sign i [e.1, cj.1] },
   { er := er, cj := cj.1, kj := cj.2 })

def s2kResp (i j : Nat) (msg : S2KInitMsg) : Option (Ciphertext × Key) :=
  if verify i [msg.epk, msg.cj] msg.sigma then
    let ec := wEncaps msg.epk
    let kj := kemDecaps j msg.cj
    some (ec.1, H [i, j, msg.epk, ec.1, msg.cj, kj, ec.2])
  else
    none

def s2kFinal (i j : Nat) (st : S2KState) (ec : Ciphertext) : Key :=
  let e := wGen (G i st.er)
  let ek := wDecaps e.2 ec
  H [i, j, e.1, ec, st.cj, st.kj, ek]

theorem s2k_honest_agreement (i j er : Randomness) :
    ∃ out, s2kResp i j (s2kInit i j er).1 = some out ∧
      s2kFinal i j (s2kInit i j er).2 out.1 = out.2 := by
  let m := s2kInit i j er
  refine ⟨((wGen (G i er)).1 + 1,
    H [i, j, (wGen (G i er)).1, (wGen (G i er)).1 + 1,
       (kemEncaps j).1, (kemEncaps j).2, (wGen (G i er)).1 + 2]), ?_, ?_⟩
  · simp [m, s2kResp, s2kInit, verify, sign]
  · simp [m, s2kFinal, s2kInit, G, H, wGen, wEncaps, wDecaps, kemEncaps, kemDecaps]

theorem s2k_wrong_initiator_signature_rejected
    (i j er : Randomness) (bad : Sig)
    (hbad : bad ≠ sign i [(wGen (G i er)).1, (kemEncaps j).1]) :
    s2kResp i j
      { epk := (wGen (G i er)).1,
        cj := (kemEncaps j).1,
        sigma := bad } = none := by
  simp [s2kResp, verify, hbad]

/-! K2K: both credentials are KEMs, and the initiator's ephemeral/second key
is regenerated from `r` and its long-term secret. -/

structure K2KInitMsg where
  epk : Pub
  cj : Ciphertext
  deriving Repr, DecidableEq

structure K2KState where
  r : Randomness
  kj : Key
  cj : Ciphertext
  deriving Repr, DecidableEq

def k2kInit (i j r : Randomness) : K2KInitMsg × K2KState :=
  let e := twoGen2 (G i r)
  let cj := kemEncaps j
  ({ epk := e.1, cj := cj.1 },
   { r := r, kj := cj.2, cj := cj.1 })

def k2kResp (i j : Nat) (msg : K2KInitMsg) : Ciphertext × Key :=
  let ci := twoEncaps i msg.epk
  let kj := kemDecaps j msg.cj
  (ci.1, H [i, j, msg.epk, ci.1, msg.cj, ci.2, kj])

def k2kFinal (i j : Nat) (st : K2KState) (ci : Ciphertext) : Key :=
  let e := twoGen2 (G i st.r)
  let ki := twoDecaps i e.2 ci
  H [i, j, e.1, ci, st.cj, ki, st.kj]

theorem k2k_honest_agreement (i j r : Randomness) :
    let out := k2kResp i j (k2kInit i j r).1
    k2kFinal i j (k2kInit i j r).2 out.1 = out.2 := by
  simp [k2kFinal, k2kResp, k2kInit, twoGen2, twoEncaps, twoDecaps,
        kemEncaps, kemDecaps, G, H]

theorem k2k_state_reconstructs_ephemeral (i r : Randomness) :
    (twoGen2 (G i (k2kInit i 0 r).2.r)).1 =
      (k2kInit i 0 r).1.epk := by
  simp [k2kInit, twoGen2]

/-! S2S: both credentials are signatures; only the ephemeral KEM contributes
a secret. -/

structure S2SInitMsg where
  epk : Pub
  sigmaI : Sig
  deriving Repr, DecidableEq

structure S2SRespMsg where
  ec : Ciphertext
  sigmaR : Sig
  deriving Repr, DecidableEq

def s2sInit (i er : Randomness) : S2SInitMsg × Randomness :=
  let e := wGen (G i er)
  ({ epk := e.1, sigmaI := sign i [e.1] }, er)

def s2sResp (i j : Nat) (msg : S2SInitMsg) : Option (S2SRespMsg × Key) :=
  if verify i [msg.epk] msg.sigmaI then
    let ec := wEncaps msg.epk
    some ({ ec := ec.1, sigmaR := sign j [msg.epk, ec.1] },
          H [i, j, msg.epk, ec.1, ec.2])
  else
    none

def s2sFinal (i j : Nat) (er : Randomness) (msg : S2SRespMsg) : Option Key :=
  let e := wGen (G i er)
  if verify j [e.1, msg.ec] msg.sigmaR then
    let ek := wDecaps e.2 msg.ec
    some (H [i, j, e.1, msg.ec, ek])
  else
    none

theorem s2s_honest_agreement (i j er : Randomness) :
    ∃ out, s2sResp i j (s2sInit i er).1 = some out ∧
      s2sFinal i j (s2sInit i er).2 out.1 = some out.2 := by
  let e := wGen (G i er)
  refine ⟨({ ec := e.1 + 1, sigmaR := j + H [e.1, e.1 + 1] },
    H [i, j, e.1, e.1 + 1, e.1 + 2]), ?_, ?_⟩
  · simp [s2sResp, s2sInit, e, verify, sign]
  · simp [s2sFinal, s2sInit, e, wGen, wEncaps, wDecaps, verify, sign]

theorem s2s_wrong_initiator_signature_rejected
    (i j er : Randomness) (bad : Sig) (hbad : bad ≠ sign i [(wGen (G i er)).1]) :
    s2sResp i j { epk := (wGen (G i er)).1, sigmaI := bad } = none := by
  simp [s2sResp, verify, hbad]

/-! This is the concrete cross-profile context collision: the S2S responder
signature on `epk || ec` is exactly a syntactically valid S2K initiator
signature under the same signature key when it is interpreted with `cj = ec`.
No framework/role tag is involved. -/
theorem s2s_responder_signature_is_accepted_as_s2k_initiator
    (b r er : Randomness) :
    let epk := (wGen (G b er)).1
    let ec := (wEncaps epk).1
    ∃ out,
      s2kResp b r
        ({ epk := epk, cj := ec, sigma := sign b [epk, ec] } :
          S2KInitMsg) = some out := by
  simp [s2kResp, verify, sign]

end CreTAKE
