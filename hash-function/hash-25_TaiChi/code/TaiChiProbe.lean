import Mathlib

namespace TaiChiProbe

def sbox (a0 a1 a2 a3 a4 : Bool) : Bool × Bool × Bool × Bool × Bool :=
  ( a1 ^^ (a0 && a1) ^^ a2 ^^ (a1 && a2) ^^ a3 ^^ (a3 && a4),
    true ^^ a1 ^^ (a0 && a3) ^^ (a1 && a3) ^^ a4 ^^ (a2 && a4),
    (a1 && a2) ^^ a3 ^^ (a2 && a3) ^^ a4 ^^ (a0 && a4),
    (a0 && a2) ^^ (a1 && a3) ^^ (a2 && a3) ^^ a4,
    a0 ^^ (a2 && a3) ^^ (a1 && a4) )

theorem sbox_01011_eq_sbox_01111 :
    sbox true true false true false = sbox true true true true false := by
  native_decide

example :
    sbox true true false true false = (true, false, true, true, true) := by
  native_decide

example :
    sbox true true true true false = (true, false, true, true, true) := by
  native_decide

end TaiChiProbe
