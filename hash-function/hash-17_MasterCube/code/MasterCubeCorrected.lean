import Init.Data.BitVec

/-!
Lean core for the corrected MasterCube v2.0 one-round inverse.

`step` is one printed 16-bit AndRX step.  The theorem is independent of
the particular rotation/AND/XOR function `f`, hence applies to every one
of the six printed MAndRX rounds.
-/

namespace MasterCubeCorrected

abbrev Cell := BitVec 16

def step (f : Cell → Cell) (p : Cell × Cell) : Cell × Cell :=
  ((f p.1) ^^^ p.2, p.1)

def invStep (f : Cell → Cell) (p : Cell × Cell) : Cell × Cell :=
  (p.2, p.1 ^^^ (f p.2))

theorem invStep_step (f : Cell → Cell) (L R : Cell) :
    invStep f (step f (L, R)) = (L, R) := by
  simp [invStep, step, BitVec.xor_assoc]

theorem step_invStep (f : Cell → Cell) (L R : Cell) :
    step f (invStep f (L, R)) = (L, R) := by
  simp [invStep, step, BitVec.xor_assoc]

end MasterCubeCorrected
