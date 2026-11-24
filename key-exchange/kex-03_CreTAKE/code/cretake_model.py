#!/usr/bin/env python3
"""Executable abstract wiring model for the four CreTAKE exchanges."""

from dataclasses import dataclass
from typing import Optional


def H(xs):
    acc = 17
    for x in xs:
        acc = acc * 31 + x + 1
    return acc


def G(sk, er):
    return H([sk, er])


def wGen(r):
    return r, r


def wEncaps(pk):
    return pk + 1, pk + 2


def wDecaps(sk, _ct):
    return sk + 2


def kemGen(i):
    return i, i


def kemEncaps(pk):
    return pk + 3, pk + 4


def kemDecaps(sk, _ct):
    return sk + 4


def twoGen1(i):
    return i, i


def twoGen2(r):
    return r, r


def twoEncaps(pk1, pk2):
    return pk1 + pk2 + 5, pk1 + pk2 + 6


def twoDecaps(sk1, sk2, _ct):
    return sk1 + sk2 + 6


def sign(sk, message):
    return sk + H(message)


def verify(pk, message, sigma):
    return sigma == pk + H(message)


def k2s(i, j, r):
    epk, fsk = wGen(r)
    ec, ek = wEncaps(epk)
    ci, ki = kemEncaps(i)
    sigma = sign(j, [epk, ec, ci])
    responder_key = H([i, j, epk, ec, ci, ki, ek])
    accepted = verify(j, [epk, ec, ci], sigma)
    ek2 = wDecaps(fsk, ec)
    ki2 = kemDecaps(i, ci)
    initiator_key = H([i, j, epk, ec, ci, ki2, ek2])
    return accepted, responder_key, initiator_key


def s2k_init(i, j, er):
    epk, fsk = wGen(G(i, er))
    cj, kj = kemEncaps(j)
    return (epk, cj, sign(i, [epk, cj])), (er, cj, kj, fsk, epk)


def s2k_resp(i, j, msg):
    epk, cj, sigma = msg
    if not verify(i, [epk, cj], sigma):
        return None
    ec, ek = wEncaps(epk)
    kj = kemDecaps(j, cj)
    return ec, H([i, j, epk, ec, cj, kj, ek])


def s2k_final(i, j, state, ec):
    er, cj, kj, fsk, epk = state
    assert epk == wGen(G(i, er))[0]
    ek = wDecaps(fsk, ec)
    return H([i, j, epk, ec, cj, kj, ek])


def k2k(i, j, r):
    epk, esk = twoGen2(G(i, r))
    cj, kj = kemEncaps(j)
    ci, ki = twoEncaps(i, epk)
    responder_key = H([i, j, epk, ci, cj, ki, kj])
    epk2, esk2 = twoGen2(G(i, r))
    assert (epk, esk) == (epk2, esk2)
    ki2 = twoDecaps(i, esk2, ci)
    initiator_key = H([i, j, epk2, ci, cj, ki2, kj])
    return responder_key, initiator_key


@dataclass(frozen=True)
class S2SMsg:
    epk: int
    sigma_i: int


@dataclass(frozen=True)
class S2SResp:
    ec: int
    sigma_r: int


def s2s_init(i, er):
    epk, fsk = wGen(G(i, er))
    return S2SMsg(epk, sign(i, [epk])), (er, fsk, epk)


def s2s_resp(i, j, msg):
    if not verify(i, [msg.epk], msg.sigma_i):
        return None
    ec, ek = wEncaps(msg.epk)
    return S2SResp(ec, sign(j, [msg.epk, ec])), H([i, j, msg.epk, ec, ek])


def s2s_final(i, j, state, msg):
    er, fsk, epk = state
    if not verify(j, [epk, msg.ec], msg.sigma_r):
        return None
    ek = wDecaps(fsk, msg.ec)
    return H([i, j, epk, msg.ec, ek])


def cross_profile_signature_reuse(attacker, victim, er):
    """The victim's S2S responder signature is accepted in S2K as its
    initiator signature.  The ciphertext is intentionally not valid under the
    S2K responder key; implicit rejection still returns a key."""
    first, _ = s2s_init(attacker, er)
    produced = s2s_resp(attacker, victim, first)
    assert produced is not None
    victim_msg, victim_key = produced
    s2k_claim = (first.epk, victim_msg.ec, victim_msg.sigma_r)
    accepted = s2k_resp(victim, 777, s2k_claim)
    assert accepted is not None
    _, s2k_responder_key = accepted
    return {
        "victim_s2s_key": victim_key,
        "s2k_responder_key": s2k_responder_key,
        "identical_signed_components": (first.epk, victim_msg.ec),
        "replayed_signature": victim_msg.sigma_r,
        "s2k_resp_accepted": True,
    }


def finite_checks():
    points = range(6)
    for i, j, r in ((i, j, r) for i in points for j in points for r in points):
        accepted, kr, ki = k2s(i, j, r)
        assert accepted and kr == ki
        first, state = s2k_init(i, j, r)
        out = s2k_resp(i, j, first)
        assert out is not None and s2k_final(i, j, state, out[0]) == out[1]
        kr, ki = k2k(i, j, r)
        assert kr == ki
        first, state = s2s_init(i, r)
        out = s2s_resp(i, j, first)
        assert out is not None and s2s_final(i, j, state, out[0]) == out[1]


def polar_cca_honest_key_swap(seed: int, encapsulated_key: int) -> tuple[int, int]:
    """Figure 6: Enc returns the second G output as K, while Dec reads the
    first G output as K.  On re-encryption success it returns that first value.
    """
    encaps_key = encapsulated_key
    decaps_key = seed
    return encaps_key, decaps_key


def polar_tuple_order_consequences():
    seed, encapsulated_key = 0x12345, 0xabcde
    left, right = polar_cca_honest_key_swap(seed, encapsulated_key)
    assert left != right

    # K2S: responder has ki=second output; initiator's Decaps returns first.
    transcript = [3, 5, 7, 11, 13]
    assert H(transcript + [left]) != H(transcript + [right])

    # S2K: initiator stores kj=second output; responder's Decaps returns first.
    assert H(transcript + [right]) != H(transcript + [left])

    # Generic K2K at 128/256: initiator stores kj=second output, responder
    # obtains first output from Decaps(skj,cj).
    assert H(transcript + [left]) != H(transcript + [right])
    return left, right


if __name__ == "__main__":
    finite_checks()
    print("checked 216 parameter triples: all four honest key equations agree")
    print(cross_profile_signature_reuse(attacker=11, victim=12, er=5))
    print("PolarLAC CCA honest encaps/decaps keys:", polar_tuple_order_consequences())
