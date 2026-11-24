import Init.Data.BitVec

/-!
Core finite identity used by the MasterCube v2.0 MAndRX check.

The six concrete rotation functions are left abstract: the inverse theorem
below is valid for every function on 16-bit cells, hence for each printed
MAndRX round function.
-/

namespace MasterCube

abbrev Cell := BitVec 16

def step (f : Cell -> Cell) (p : Cell × Cell) : Cell × Cell :=
  ((f p.1) ^^^ p.2, p.1)

def invStep (f : Cell -> Cell) (p : Cell × Cell) : Cell × Cell :=
  (p.2, p.1 ^^^ (f p.2))

theorem invStep_step (f : Cell -> Cell) (L R : Cell) :
    invStep f (step f (L, R)) = (L, R) := by
  simp [invStep, step, BitVec.xor_assoc]

theorem step_invStep (f : Cell -> Cell) (L R : Cell) :
    step f (invStep f (L, R)) = (L, R) := by
  simp [invStep, step, BitVec.xor_assoc]

end MasterCube
