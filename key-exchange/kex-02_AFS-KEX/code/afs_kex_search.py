#!/usr/bin/env python3
"""Bounded executable model for AFS-KEX spec v1.0 pp.10-12.

This is an exploratory/reproducibility artifact, not a crypto_run-backed
research-evidence job.  It has two independent checks:

1. A bounded symbolic network search for pMAKE-BW and pUAKE-BW.  KEM keys,
   PRF/PRG outputs, and seed masks are symbolic deterministic objects.  The
   adversary may replay messages and rewrite one protocol field at a time.
2. A concrete toy BW-PKE/FO instance showing that BW-KEM.Decaps called with
   the same declared (csk,ct) but different ambient pk values returns
   different keys.  This witnesses the interface ambiguity in Fig.2.

The symbolic negative search is bounded and is not a general security proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import deque
from dataclasses import dataclass, replace, field
from itertools import product
from pathlib import Path
from typing import Any, Iterable


PARTIES = ("A", "B")
IDS = ("A", "B", "X")
SESSIONS_PER_PARTY_ROLE = 2
MAX_EVENTS = 8
MAX_STATES = 500


def H(*items: Any) -> str:
    return "H(" + ",".join(map(str, items)) + ")"


def H1(*items: Any) -> str:
    return "H1(" + ",".join(map(str, items)) + ")"


def PRF(*items: Any) -> tuple[str, str, str]:
    stem = "PRF(" + ",".join(map(str, items)) + ")"
    return stem + ":KS", stem + ":KAENC", stem + ":KBENC"


def PRG(*items: Any) -> tuple[str, str]:
    stem = "PRG(" + ",".join(map(str, items)) + ")"
    return stem + ":KS", stem + ":KENC"


def XOR(mask: str, seed: str) -> str:
    return f"XOR({mask},{seed})"


@dataclass(frozen=True)
class StaticKey:
    ident: str
    rho: str
    t: str
    s: str
    z: str


def static_keys() -> dict[str, StaticKey]:
    return {
        u: StaticKey(u, f"rho_{u}", f"t_{u}", f"s_{u}", f"z_{u}")
        for u in PARTIES
    }


KA = static_keys()
CA = {("A", KA["A"].t, KA["A"].rho), ("B", KA["B"].t, KA["B"].rho)}


@dataclass(frozen=True)
class CPK:
    base_party: str
    sid: int
    t: str
    rho: str
    csk: str

    def token(self) -> str:
        return f"cpk[{self.base_party}:{self.sid}:{self.t}:{self.rho}]"


def make_cpk(party: str, sid: int, t_override: str | None = None,
             rho_override: str | None = None) -> CPK:
    k = KA[party]
    return CPK(party, sid, t_override or f"tc_{party}_{sid}",
               rho_override or k.rho, f"csk_{party}_{sid}")


@dataclass(frozen=True)
class CT:
    pk: str
    msg: str
    key: str

    def token(self) -> str:
        return f"ct[{self.pk}:{self.msg}:{self.key}]"


def encaps(cpk: CPK) -> tuple[CT, str]:
    msg = f"m({cpk.token()})"
    key = H(cpk.token(), msg)
    return CT(cpk.token(), msg, key), key


def decaps(cpk_for_ro: CPK, actual_cpk: CPK, ct: CT) -> str:
    """FO behavior sufficient for the protocol correlation search.

    ct decrypts correctly exactly when it targets actual_cpk.  Re-encryption
    succeeds only if the caller's pk and the csk's associated pk coincide.
    """
    if ct.pk == actual_cpk.token() and cpk_for_ro == actual_cpk:
        return H(cpk_for_ro.token(), ct.msg)
    return H1(cpk_for_ro.token(), actual_cpk.csk.removeprefix("csk_"),
              ct.token())


def ekeygen(cpk: CPK, seed: str) -> str:
    return f"te({cpk.rho},{seed})"


def extract_static(cpk: CPK, seed: str) -> tuple[str, str]:
    te = ekeygen(cpk, seed)
    # A uniformly selected t_override is almost never the sum
    # t_static + te; model that equality exactly.
    t = f"t_static_if({cpk.t}={te})"
    return t, cpk.rho


def ca_valid(ident: str, t: str, rho: str) -> bool:
    # Symbolically evaluate the equality predicate for the two honest keys.
    # Honest cpks recover t_U exactly; tampered cpks do not.
    if ident in PARTIES and rho == KA[ident].rho:
        for i in range(SESSIONS_PER_PARTY_ROLE):
            expected = (
                f"t_static_if(tc_{ident}_{i}=te(rho_{ident},"
                f"seed_{ident}_{i}))"
            )
            if t == expected:
                return True
    return False


@dataclass(frozen=True)
class Wire:
    kind: str
    fields: tuple[Any, ...]
    provenance: str

    def text(self) -> str:
        return self.kind + "(" + ",".join(map(str, self.fields)) + ")"


@dataclass(frozen=True)
class Session:
    sid: str
    protocol: str
    role: str
    actor: str
    stage: int = 0
    own_cpk: CPK | None = None
    peer_cpk: CPK | None = None
    ct_recv: CT | None = None
    ct_sent: CT | None = None
    peer_key: str | None = None
    seed: str | None = None
    masks: tuple[str, ...] = ()
    accepted: bool = False
    session_key: str | None = None


@dataclass(frozen=True)
class State:
    sessions: tuple[Session, ...]
    network: tuple[Wire, ...]
    events: tuple[str, ...] = ()
    log: tuple[str, ...] = ()


def sid_list(protocol: str) -> tuple[str, ...]:
    return tuple(
        f"{protocol}:{role}:{u}:{i}"
        for role in ("I", "R")
        for u in PARTIES
        for i in range(SESSIONS_PER_PARTY_ROLE)
    )


def initial_state(protocol: str) -> State:
    sessions: list[Session] = []
    network: list[Wire] = []
    logs: list[str] = []
    for u in PARTIES:
        for i in range(SESSIONS_PER_PARTY_ROLE):
            sr = f"{protocol}:R:{u}:{i}"
            sessions.append(Session(sr, protocol, "R", u))
            si = f"{protocol}:I:{u}:{i}"
            cpk = make_cpk(u, i)
            seed = f"seed_{u}_{i}"
            sessions.append(Session(si, protocol, "I", u, stage=1,
                                    own_cpk=cpk, seed=seed))
            wire = Wire("M1", (cpk.token(),), si)
            network.append(wire)
            logs.append(f"{si} Round1 sends {wire.text()}")
    return State(tuple(sessions), tuple(network), (), tuple(logs))


def replace_session(state: State, old: Session, new: Session) -> State:
    return replace(
        state,
        sessions=tuple(new if s.sid == old.sid else s for s in state.sessions),
    )


def add_wire(state: State, wire: Wire) -> State:
    return replace(state, network=state.network + (wire,))


def cpk_variants() -> tuple[CPK, ...]:
    out: list[CPK] = []
    tamper_t = ("foreign_t", "t_A_0", "t_B_0")
    tamper_rho = ("foreign_rho", "rho_A", "rho_B")
    for protocol in ("pMAKE", "pUAKE"):
        del protocol
        break
    for u in PARTIES:
        for i in range(SESSIONS_PER_PARTY_ROLE):
            out.append(make_cpk(u, i))
            out.append(make_cpk(u, i, t_override=tamper_t[(i + (u == "B")) % 3]))
            out.append(make_cpk(u, i, rho_override=tamper_rho[(i + (u == "B")) % 3]))
    # De-duplicate while preserving order.
    return tuple(dict.fromkeys(out))


CPKS = cpk_variants()


def parse_cpk_token(tok: str) -> CPK | None:
    for c in CPKS:
        if c.token() == tok:
            return c
    return None


def ct_variants(protocol: str) -> tuple[CT, ...]:
    out: list[CT] = []
    for u in PARTIES:
        for i in range(SESSIONS_PER_PARTY_ROLE):
            c = make_cpk(u, i)
            ct, _ = encaps(c)
            out.append(ct)
    out.append(CT("foreign_pk", "foreign_m", "foreign_key"))
    return tuple(dict.fromkeys(out))


def parse_ct_token(tok: str, cts: tuple[CT, ...]) -> CT | None:
    for c in cts:
        if c.token() == tok:
            return c
    return None


def outputs_for_delivery(protocol: str, sess: Session, wire: Wire
                         ) -> tuple[Session, list[Wire], list[str]] | None:
    if protocol == "pUAKE":
        if sess.role == "R" and sess.stage == 0 and wire.kind == "M1":
            cpk = parse_cpk_token(wire.fields[0])
            if cpk is None:
                return None
            ct, K = encaps(cpk)
            s2 = replace(sess, stage=1, peer_cpk=cpk, ct_sent=ct,
                         peer_key=K)
            m2 = Wire("M2", (ct.token(),), sess.sid)
            return s2, [m2], [f"{sess.sid} Round2 sends {m2.text()}"]
        if sess.role == "I" and sess.stage == 1 and wire.kind == "M2":
            ct = parse_ct_token(wire.fields[0], ct_variants(protocol))
            if ct is None or sess.own_cpk is None:
                return None
            kp = decaps(sess.own_cpk, sess.own_cpk, ct)
            ks, mask = PRG(kp)
            seed = sess.seed or ""
            s3 = replace(sess, stage=2, ct_recv=ct, peer_key=kp,
                         masks=(mask,), session_key=ks, accepted=True)
            m3 = Wire("M3", ("A", XOR(mask, seed)), sess.sid)
            return s3, [m3], [
                f"{sess.sid} Decaps gives {kp}; PRG gives ({ks},{mask})",
                f"{sess.sid} accepts {ks} before Round3",
                f"{sess.sid} Round3 sends {m3.text()}",
            ]
        if sess.role == "R" and sess.stage == 1 and wire.kind == "M3":
            ident, cseed = wire.fields
            if sess.peer_cpk is None or sess.peer_key is None:
                return None
            ks, mask = PRG(sess.peer_key)
            seed = cseed.removeprefix(f"XOR({mask},").removesuffix(")")
            t, rho = extract_static(sess.peer_cpk, seed)
            ok = ca_valid(ident, t, rho)
            s3 = replace(sess, stage=2, accepted=ok,
                         session_key=ks if ok else None)
            return s3, [], [
                f"{sess.sid} PRG gives ({ks},{mask}); recovers {seed}; "
                f"CAVerf({ident},{t},{rho})={int(ok)}"
            ]
    if protocol == "pMAKE":
        if sess.role == "R" and sess.stage == 0 and wire.kind == "M1":
            cpk = parse_cpk_token(wire.fields[0])
            if cpk is None:
                return None
            own = make_cpk(sess.actor, int(sess.sid.rsplit(":", 1)[1]))
            seed = f"seed_{sess.actor}_{sess.sid.rsplit(':', 1)[1]}"
            ct, KA_key = encaps(cpk)
            m2 = Wire("M2", (own.token(), ct.token()), sess.sid)
            s2 = replace(sess, stage=1, peer_cpk=cpk, own_cpk=own,
                         seed=seed, peer_key=KA_key, ct_sent=ct)
            return s2, [m2], [f"{sess.sid} Round2 sends {m2.text()}"]
        if sess.role == "I" and sess.stage == 1 and wire.kind == "M2":
            cpk_tok, ct_tok = wire.fields
            peer_cpk = parse_cpk_token(cpk_tok)
            ct = parse_ct_token(ct_tok, ct_variants(protocol))
            if peer_cpk is None or ct is None or sess.own_cpk is None:
                return None
            kp = decaps(sess.own_cpk, sess.own_cpk, ct)
            ctB, KB = encaps(peer_cpk)
            ks, ma, mb = PRF(kp, KB)
            seed = sess.seed or ""
            m3 = Wire("M3", ("A", ctB.token(), XOR(ma, seed)), sess.sid)
            s3 = replace(sess, stage=2, peer_cpk=peer_cpk, ct_recv=ct,
                         ct_sent=ctB, peer_key=kp, masks=(ma, mb),
                         session_key=ks)
            return s3, [m3], [
                f"{sess.sid} Decaps gives {kp}; Round3 sends {m3.text()}"
            ]
        if sess.role == "R" and sess.stage == 1 and wire.kind == "M3":
            ident, ct_tok, cseed = wire.fields
            ct = parse_ct_token(ct_tok, ct_variants(protocol))
            if ct is None or sess.own_cpk is None or sess.peer_key is None:
                return None
            kp = decaps(sess.own_cpk, sess.own_cpk, ct)
            ks, ma, mb = PRF(sess.peer_key, kp)
            seed = cseed.removeprefix(f"XOR({ma},").removesuffix(")")
            t, rho = extract_static(sess.peer_cpk, seed)
            ok = ca_valid(ident, t, rho) if sess.peer_cpk else False
            s4 = replace(sess, stage=2, peer_key=kp, masks=(ma, mb),
                         session_key=ks if ok else None, accepted=False)
            if ok:
                m4 = Wire("M4", ("B", XOR(mb, sess.seed or "")), sess.sid)
                s4 = replace(s4, accepted=True)
                return s4, [m4], [
                    f"{sess.sid} PRF gives ({ks},{ma},{mb}); recovers {seed}; "
                    f"CAVerf={int(ok)}; accepts {ks}; sends {m4.text()}"
                ]
            return s4, [], [f"{sess.sid} CAVerf={int(ok)}; aborts"]
        if sess.role == "I" and sess.stage == 2 and wire.kind == "M4":
            ident, cseed = wire.fields
            if sess.peer_cpk is None or len(sess.masks) < 2:
                return None
            mb = sess.masks[1]
            seed = cseed.removeprefix(f"XOR({mb},").removesuffix(")")
            t, rho = extract_static(sess.peer_cpk, seed)
            ok = ca_valid(ident, t, rho)
            s4 = replace(sess, stage=3, accepted=ok,
                         session_key=sess.session_key if ok else None)
            return s4, [], [
                f"{sess.sid} recovers {seed}; CAVerf({ident},{t},{rho})={int(ok)}"
            ]
    return None


def variants_for_wire(protocol: str, wire: Wire) -> Iterable[Wire]:
    yield wire
    cts = ct_variants(protocol)
    if wire.kind == "M1":
        for c in CPKS:
            if c.token() != wire.fields[0]:
                yield Wire("M1", (c.token(),), f"rewrite:{wire.provenance}")
    elif wire.kind == "M2" and protocol == "pUAKE":
        for c in cts:
            if c.token() != wire.fields[0]:
                yield Wire("M2", (c.token(),), f"rewrite:{wire.provenance}")
    elif wire.kind == "M2" and protocol == "pMAKE":
        for c in CPKS:
            if c.token() != wire.fields[0]:
                yield Wire("M2", (c.token(), wire.fields[1]),
                           f"rewrite-cpk:{wire.provenance}")
        for ct in cts:
            if ct.token() != wire.fields[1]:
                yield Wire("M2", (wire.fields[0], ct.token()),
                           f"rewrite-ct:{wire.provenance}")
    elif wire.kind == "M3" and protocol == "pUAKE":
        for ident in IDS:
            yield Wire("M3", (ident, wire.fields[1]), f"rewrite-id:{wire.provenance}")
        mask = wire.fields[1].split(",", 1)[0].removeprefix("XOR(")
        for seed in ("seed_A_0", "seed_A_1", "seed_B_0", "seed_B_1", "junk"):
            c = XOR(mask, seed)
            if c != wire.fields[1]:
                yield Wire("M3", (wire.fields[0], c),
                           f"rewrite-seed:{wire.provenance}")
    elif wire.kind == "M3" and protocol == "pMAKE":
        for ident in IDS:
            yield Wire("M3", (ident, wire.fields[1], wire.fields[2]),
                       f"rewrite-id:{wire.provenance}")
        for ct in cts:
            if ct.token() != wire.fields[1]:
                yield Wire("M3", (wire.fields[0], ct.token(), wire.fields[2]),
                           f"rewrite-ct:{wire.provenance}")
        mask = wire.fields[2].split(",", 1)[0].removeprefix("XOR(")
        for seed in ("seed_A_0", "seed_A_1", "seed_B_0", "seed_B_1", "junk"):
            c = XOR(mask, seed)
            if c != wire.fields[2]:
                yield Wire("M3", (wire.fields[0], wire.fields[1], c),
                           f"rewrite-seed:{wire.provenance}")
    elif wire.kind == "M4":
        for ident in IDS:
            yield Wire("M4", (ident, wire.fields[1]), f"rewrite-id:{wire.provenance}")
        mask = wire.fields[1].split(",", 1)[0].removeprefix("XOR(")
        for seed in ("seed_A_0", "seed_A_1", "seed_B_0", "seed_B_1", "junk"):
            c = XOR(mask, seed)
            if c != wire.fields[1]:
                yield Wire("M4", (wire.fields[0], c),
                           f"rewrite-seed:{wire.provenance}")


def acceptance_anomaly(protocol: str, state: State) -> str | None:
    accepted = [s for s in state.sessions if s.accepted]
    if protocol == "pUAKE":
        for r in accepted:
            if r.role != "R":
                continue
            peers = [i for i in accepted
                     if i.role == "I" and i.actor == r.peer_cpk.base_party
                     and i.session_key == r.session_key]
            if not peers:
                return f"unmatched pUAKE responder acceptance {r}"
    else:
        # In pMAKE the responder commits/accepts at Round 4 before its final
        # message reaches the initiator.  The checkable malformed event is an
        # initiator acceptance without a matching accepted responder.
        for x in accepted:
            if x.role != "I":
                continue
            peers = [y for y in accepted if y.role != x.role
                     and y.session_key == x.session_key]
            if not peers:
                return f"unmatched pMAKE acceptance {x}"
    return None


def search_protocol(protocol: str) -> dict[str, Any]:
    q: deque[State] = deque([initial_state(protocol)])
    seen: set[State] = set(q)
    explored = 0
    transitions = 0
    accepts = 0
    stop_reason = "state_limit"
    while q and explored < MAX_STATES:
        state = q.popleft()
        explored += 1
        if len(state.events) >= MAX_EVENTS:
            continue
        anomaly = acceptance_anomaly(protocol, state)
        if anomaly:
            return {
                "protocol": protocol,
                "status": "anomaly_found",
                "anomaly": anomaly,
                "explored": explored,
                "events": state.events,
                "trace": state.log,
            }
        if any(s.accepted for s in state.sessions):
            accepts += 1
        for wi, wire in enumerate(state.network):
            for variant in variants_for_wire(protocol, wire):
                for si, sess in enumerate(state.sessions):
                    out = outputs_for_delivery(protocol, sess, variant)
                    if out is None:
                        continue
                    newsess, outputs, logs = out
                    ns = replace_session(state, sess, newsess)
                    # Consume the delivered wire.  Replaying an identical
                    # wire after the same eligible receiver has advanced
                    # produces no new transition; delivery to every eligible
                    # concurrent session is explored before consumption.
                    ns = replace(ns, network=ns.network[:wi] + ns.network[wi + 1:])
                    for w in outputs:
                        ns = add_wire(ns, w)
                    event = f"deliver[{wi}]={variant.text()}->{sess.sid}"
                    ns = replace(ns, events=state.events + (event,),
                                 log=state.log + tuple(logs))
                    transitions += 1
                    if ns not in seen:
                        seen.add(ns)
                        q.append(ns)
        # Drop a wire; this changes state and models loss/reordering.
        if state.network:
            ns = replace(state, network=state.network[:-1],
                         events=state.events + ("drop-last",),
                         log=state.log + ("drop last wire",))
            transitions += 1
            if ns not in seen:
                seen.add(ns)
                q.append(ns)
    if not q:
        stop_reason = "exhausted"
    return {
        "protocol": protocol,
        "status": "no_anomaly_in_bound",
        "bounds": {
            "parties": len(PARTIES),
            "sessions_per_party_role": SESSIONS_PER_PARTY_ROLE,
            "max_delivery_or_drop_events": MAX_EVENTS,
            "max_states": MAX_STATES,
            "rewrite_model": "exact message or one-field rewrite from finite token pool",
        },
        "explored": explored,
        "transitions": transitions,
        "states_with_acceptance": accepts,
        "stop_reason": stop_reason,
    }


# Concrete toy BW-PKE instance for the Decaps-pk ambiguity.
Q = 97
D = 4


def digest(*items: Any) -> int:
    h = hashlib.sha256("\x1f".join(map(repr, items)).encode()).digest()
    return int.from_bytes(h[:8], "big")


def mat_from_rho(rho: bytes) -> list[list[int]]:
    out = []
    ctr = 0
    while len(out) < D * D:
        block = hashlib.sha256(rho + ctr.to_bytes(4, "big")).digest()
        ctr += 1
        for b in block:
            out.append(b % Q)
            if len(out) == D * D:
                break
    return [out[i * D:(i + 1) * D] for i in range(D)]


def small(*items: Any) -> list[int]:
    h = hashlib.sha256("\x1f".join(map(repr, items)).encode()).digest()
    return [int(b % 3) - 1 for b in h[:D]]


def add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % Q for x, y in zip(a, b)]


def sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % Q for x, y in zip(a, b)]


def mat_vec(A: list[list[int]], v: list[int]) -> list[int]:
    return [sum(A[i][j] * v[j] for j in range(D)) % Q for i in range(D)]


def matT_vec(A: list[list[int]], v: list[int]) -> list[int]:
    return [sum(A[i][j] * v[i] for i in range(D)) % Q for j in range(D)]


def dot(a: list[int], b: list[int]) -> int:
    return sum(x * y for x, y in zip(a, b)) % Q


def bitmsg(n: int, m: int) -> list[int]:
    return [Q // 2 if (m >> i) & 1 else 0 for i in range(n)]


def keypair() -> tuple[dict[str, Any], dict[str, Any]]:
    rho = b"rho-static"
    A = mat_from_rho(rho)
    s = small("s")
    e = small("e")
    t = add(mat_vec(A, s), e)
    return ({"A": A, "rho": rho, "t": t},
            {"s": s, "z": b"z-static"})


def toy_ekeygen(pk: dict[str, Any], seed: bytes
                ) -> tuple[dict[str, Any], dict[str, Any]]:
    A = mat_from_rho(pk["rho"])
    se = small(seed, "se")
    ee = small(seed, "ee")
    te = add(mat_vec(A, se), ee)
    return ({"A": A, "rho": pk["rho"], "t": te}, {"se": se})


def combine(pk: dict[str, Any], sk: dict[str, Any],
            pke: dict[str, Any], ske: dict[str, Any]
            ) -> tuple[dict[str, Any], dict[str, Any]]:
    return ({"A": pk["A"], "rho": pk["rho"], "t": add(pk["t"], pke["t"])},
            {"s": add(sk["s"], ske["se"]), "z": sk["z"]})


def pk_id(pk: dict[str, Any]) -> bytes:
    h = hashlib.sha256()
    h.update(pk["rho"])
    h.update(bytes(pk["t"]))
    return h.digest()


def H2(pk: dict[str, Any], m: int) -> tuple[bytes, bytes]:
    z = hashlib.sha256(b"H" + pk_id(pk) + m.to_bytes(8, "big")).digest()
    return z[:16], z[16:32]


def Hrej(pk: dict[str, Any], z: bytes, c: tuple[Any, ...]) -> bytes:
    return hashlib.sha256(b"H1" + pk_id(pk) + z + repr(c).encode()).digest()[:16]


def pke_enc(pk: dict[str, Any], m: int, r: bytes
            ) -> tuple[tuple[list[int], list[int]], bytes]:
    A = pk["A"]
    rv = small(r, "r")
    e1 = small(r, "e1")
    e2 = small(r, "e2")
    u = add(matT_vec(A, rv), e1)
    v = add(add([dot(pk["t"], rv)] * D, e2), bitmsg(D, m))
    return (u, v), r


def pke_dec(sk: dict[str, Any], c: tuple[list[int], list[int]]) -> int:
    u, v = c
    w = sub(v, [dot(sk["s"], u)] * D)
    m = 0
    for i, x in enumerate(w):
        d0 = min(x, Q - x)
        dh = min((x - Q // 2) % Q, (Q // 2 - x) % Q)
        if dh < d0:
            m |= 1 << i
    return m


def kem_encaps(pk: dict[str, Any], m: int) -> tuple[tuple[Any, ...], bytes]:
    K, r = H2(pk, m)
    c, _ = pke_enc(pk, m, r)
    return c, K


def kem_decaps(dec_pk: dict[str, Any], sk: dict[str, Any],
               c: tuple[Any, ...]) -> bytes:
    m = pke_dec(sk, c)
    K, r = H2(dec_pk, m)
    c2, _ = pke_enc(dec_pk, m, r)
    rej = Hrej(dec_pk, sk["z"], c)
    # Equality modulo the toy ciphertext representation.
    return rej if c2 != c else K


def cpk_witness() -> dict[str, Any]:
    pk, sk = keypair()
    pke, ske = toy_ekeygen(pk, b"seed-eph")
    cpk, csk = combine(pk, sk, pke, ske)
    # A foreign public key with the same rho and a different t.
    foreign = {"A": cpk["A"], "rho": cpk["rho"],
               "t": [(x + 1) % Q for x in cpk["t"]]}
    c, K = kem_encaps(cpk, 11)
    supplied = kem_decaps(cpk, csk, c)
    foreign_out = kem_decaps(foreign, csk, c)
    correctness_failures = []
    for m in range(1 << D):
        c_m, K_m = kem_encaps(cpk, m)
        if kem_decaps(cpk, csk, c_m) != K_m:
            correctness_failures.append(m)
    return {
        "q": Q,
        "dimension": D,
        "same_csk_sha256": hashlib.sha256(repr(csk).encode()).hexdigest(),
        "same_ct_sha256": hashlib.sha256(repr(c).encode()).hexdigest(),
        "encapsulated_key_hex": K.hex(),
        "decaps_supplied_cpk_hex": supplied.hex(),
        "decaps_foreign_cpk_hex": foreign_out.hex(),
        "supplied_matches": supplied == K,
        "foreign_matches": foreign_out == K,
        "outputs_differ": supplied != foreign_out,
        "toy_exhaustive_message_space": 1 << D,
        "toy_correctness_failures": correctness_failures,
        "cpk_t": cpk["t"],
        "foreign_t": foreign["t"],
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("protocol", "cpk", "all"), default="all")
    ap.add_argument("--out", default="afs_kex_results.json")
    args = ap.parse_args()
    result: dict[str, Any] = {
        "artifact": "afs_kex_search.py",
        "spec": {
            "url": ("https://cdn.jsdelivr.net/gh/ngcc-dev/ngcc-harness@"
                    "dc66c6cb3c06e75bdea0048e21fa4e13c63f00af/"
                    "kex-02/kex-02-spec.pdf"),
            "pdf_pages": "10-12",
            "definitions_used": "BW-KEM Fig.2 on PDF page 9",
        },
    }
    if args.mode in ("protocol", "all"):
        result["protocol_search"] = [
            search_protocol("pMAKE"),
            search_protocol("pUAKE"),
        ]
    if args.mode in ("cpk", "all"):
        result["cpk_convention_witness"] = cpk_witness()
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
