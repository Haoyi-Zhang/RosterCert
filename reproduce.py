#!/usr/bin/env python3
"""Post-hoc differential diagnostics for the finite causal-roster model.

PERMANENT CAMPAIGN WARNING: the project campaign already exceeded its declared
cumulative 600000-obligation ceiling.  This preserved runner cannot reset or
repair that breach, and no invocation creates admissible claim evidence.

For source inspection, the runner still reserves a conservative obligation
bound before each local execution.  Reservations remain charged on failure.
The tool is deterministic, uses one process, and performs no network or
cryptographic operation.
"""
from __future__ import annotations

import argparse
import copy
import csv
import fcntl
import json
import os
import resource
import tempfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
import sys
sys.path.insert(0, str(ROOT / "src"))
from cases import generate, SEED, event
from roster import Roster
from session import base_payload, delegation_payload, verify_symbolic_session
import oracle

CAMPAIGN_LIMIT = 600_000
LIMIT_SECONDS = 180
SESSION_CHECKS = 12


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"))


def independent_number(n, edges):
    best = 0
    for subset in range(1 << n):
        if all(not (subset >> a & 1 and subset >> b & 1) for a, b in edges):
            best = max(best, subset.bit_count())
    return best


def reservation_bound(cases):
    """Pre-run upper bound; does not enumerate cuts or inspect outcomes."""
    windows = 0
    total = 0
    attacks = {"stale-floor", "fork", "inactive-key", "causal-mix"}
    for case in cases:
        n = len(case["events"])
        total += 1 << n  # width search upper bound
        if case["kind"] in {"sampled-window"} | attacks:
            # family enumeration, comparison against at most every subset
            total += (1 << n) + (1 << n)
            windows += 1
        elif case["kind"] == "chain-optimization":
            total += (1 << n) + 3
        elif case["kind"] == "fork-hardness":
            total += (1 << n) + (1 << case["graph_n"])
        else:
            raise ValueError("unknown case kind")
    return total + windows // 10 + 4 + SESSION_CHECKS


def _atomic_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                                     delete=False) as handle:
        json.dump(value, handle, sort_keys=True, indent=2)
        handle.write("\n")
        tmp = Path(handle.name)
    os.replace(tmp, path)


def reserve(ledger_path: Path, label: str, amount: int) -> int:
    """Durably reserve obligations and return the entry index."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if ledger_path.exists():
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        else:
            ledger = {"schema": 1, "limit": CAMPAIGN_LIMIT,
                      "reserved_total": 0, "entries": []}
        if ledger.get("limit") != CAMPAIGN_LIMIT:
            raise RuntimeError("campaign ledger limit mismatch")
        if any(entry.get("label") == label for entry in ledger["entries"]):
            raise RuntimeError("campaign label already used")
        proposed = int(ledger["reserved_total"]) + amount
        if proposed > CAMPAIGN_LIMIT:
            raise RuntimeError(
                f"campaign reservation refused: {proposed}>{CAMPAIGN_LIMIT}"
            )
        entry = {
            "label": label,
            "reserved_obligations": amount,
            "status": "reserved",
            "actual_counted_obligations": None,
        }
        ledger["entries"].append(entry)
        ledger["reserved_total"] = proposed
        _atomic_json(ledger_path, ledger)
        fcntl.flock(lock, fcntl.LOCK_UN)
    return len(ledger["entries"]) - 1


def finish_reservation(ledger_path: Path, index: int, status: str,
                       actual: int | None, metrics: dict | None,
                       error: str | None = None) -> None:
    lock_path = ledger_path.with_suffix(ledger_path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        entry = ledger["entries"][index]
        if entry["status"] != "reserved":
            raise RuntimeError("reservation is not open")
        entry["status"] = status
        entry["actual_counted_obligations"] = actual
        if metrics is not None:
            entry["metrics"] = metrics
        if error is not None:
            entry["error"] = error[:500]
        _atomic_json(ledger_path, ledger)
        fcntl.flock(lock, fcntl.LOCK_UN)


def session_controls():
    events = [event("a", "A"), event("b", "B")]
    context = {
        "domain": "AMS-CAUSAL-ROSTER",
        "mode": "HIST",
        "application": "benign-diagnostic",
        "session": "session-001",
        "message": "approve",
        "namespace": "diagnostic-roster",
        "events": events,
        "lower": [],
        "upper": ["a", "b"],
        "cut": ["a", "b"],
        "profile": [["A", "a"], ["B", "b"]],
    }
    table = [["A", "ephemeral-A-001"], ["B", "ephemeral-B-001"]]
    delegations = {i: delegation_payload(context, table, i) for i in ("A", "B")}
    base = base_payload(context, table)
    authorizations = {i: base for i in ("A", "B")}
    if not verify_symbolic_session(context, table, delegations, authorizations):
        raise AssertionError("valid symbolic session rejected")

    mutations = []
    for field in ("domain", "application", "session", "message", "namespace"):
        bad = copy.deepcopy(context)
        bad[field] += "!"
        mutations.append((bad, table, delegations, authorizations, field))
    bad = copy.deepcopy(context); bad["mode"] = "FRESH"
    mutations.append((bad, table, delegations, authorizations, "mode"))
    bad = copy.deepcopy(context); bad["profile"] = [["A", "a"]]
    mutations.append((bad, [["A", "ephemeral-A-001"]], delegations,
                      authorizations, "profile"))
    bad = copy.deepcopy(context); bad["events"][0]["key"] = "changed"
    mutations.append((bad, table, delegations, authorizations, "event-key"))
    bad_table = [["A", "ephemeral-A-002"], ["B", "ephemeral-B-001"]]
    mutations.append((context, bad_table, delegations, authorizations,
                      "ephemeral-key"))
    bad_table = [["A", "same"], ["B", "same"]]
    mutations.append((context, bad_table, delegations, authorizations,
                      "ephemeral-alias"))
    bad_delegations = dict(delegations); del bad_delegations["B"]
    mutations.append((context, table, bad_delegations, authorizations,
                      "missing-delegation"))
    bad_authorizations = dict(authorizations)
    bad_authorizations["A"] = base + b"!"
    mutations.append((context, table, delegations, bad_authorizations,
                      "base-message"))

    if len(mutations) != SESSION_CHECKS:
        raise AssertionError("session-control count changed")
    for bad_context, bad_table, ds, bs, label in mutations:
        if verify_symbolic_session(bad_context, bad_table, ds, bs):
            raise AssertionError(f"session mutation accepted: {label}")
    return [label for *_, label in mutations]


def study(cases):
    start = time.monotonic()
    counts = Counter()
    kinds = Counter()
    rows = []
    certificates = []
    max_dim = {"events": 0, "identities": 0, "width": 0,
               "profile": 0, "per_identity_writes": 0}
    expected_attacks = {"stale-floor", "fork", "inactive-key", "causal-mix"}
    total_obligations = 0

    def account(n):
        nonlocal total_obligations
        total_obligations += n
        if total_obligations > CAMPAIGN_LIMIT:
            raise RuntimeError("enumeration ceiling exceeded")
        if time.monotonic() - start > LIMIT_SECONDS:
            raise TimeoutError("study deadline exceeded")

    for case in cases:
        ev = case["events"]
        n = len(ev)
        kind = case["kind"]
        kinds[kind] += 1
        r = Roster(ev)
        lo = r.mask(case["lower"])
        hi = r.mask(case["upper"])
        r.bounds(lo, hi)
        account(1 << n)
        width = oracle.width(ev)
        max_dim["events"] = max(max_dim["events"], n)
        max_dim["identities"] = max(max_dim["identities"], len(r.writes))
        max_dim["width"] = max(max_dim["width"], width)
        max_dim["profile"] = max(max_dim["profile"], len(case["profile"]))
        max_dim["per_identity_writes"] = max(
            max_dim["per_identity_writes"],
            max((x.bit_count() for x in r.writes.values()), default=0),
        )
        if n > 24 or len(r.writes) > 12 or width > 6:
            raise RuntimeError("declared dimension ceiling exceeded")

        if kind in {"sampled-window"} | expected_attacks:
            account(1 << n)
            inside, good = oracle.family(case)
            got = r.window(lo, hi, case["profile"])
            counts["window_queries"] += 1
            proposed = [] if got is None else [
                c for c in inside
                if set(r.names(got[0])) <= c <= set(r.names(got[1]))
            ]
            account(len(inside))
            counts["bounded_ideal_memberships"] += len(inside)
            if set(proposed) != set(good):
                raise AssertionError(f"window mismatch {case['id']}")
            if r.universal(lo, hi, case["profile"]) != (len(good) == len(inside)):
                raise AssertionError(f"universal mismatch {case['id']}")
            counts["universal_queries"] += 1
            if not case["profile"]:
                counts["empty_profiles"] += 1
            if good:
                counts["feasible_queries"] += 1
            else:
                counts["infeasible_queries"] += 1
            if kind in expected_attacks:
                if good:
                    raise AssertionError("attack-control unexpectedly feasible")
                counts["designed_infeasible_queries"] += 1
            if got and len(good) == len(inside):
                counts["universal_true"] += 1
            rows.append({
                "id": case["id"], "kind": kind, "feasible": bool(good),
                "valid_cuts": len(good),
                "window": None if got is None else [r.names(got[0]), r.names(got[1])],
                "universal": len(good) == len(inside),
            })
            if counts["window_queries"] % 10 == 0:
                rename = {e["id"]: f"z{n-i}" for i, e in enumerate(ev)}
                ee = [dict(e, id=rename[e["id"]],
                           parents=[rename[p] for p in e["parents"]])
                      for e in reversed(ev)]
                rr = Roster(ee)
                pp = {k: rename[v] for k, v in case["profile"].items()}
                gg = rr.window(
                    rr.mask([rename[x] for x in case["lower"]]),
                    rr.mask([rename[x] for x in case["upper"]]), pp,
                )
                desired = None if got is None else [
                    sorted(rename[x] for x in r.names(z)) for z in got
                ]
                result = None if gg is None else [rr.names(z) for z in gg]
                if desired != result:
                    raise AssertionError("renaming metamorphism failed")
                counts["renaming_checks"] += 1
                account(1)
        elif kind == "chain-optimization":
            account(1 << n)
            best, _ = oracle.optimum(ev, case["lower"], case["upper"])
            cert = r.optimize_chain(lo, hi)
            if best != cert["objective"]:
                raise AssertionError("max-closure optimum mismatch")
            if not oracle.replay_flow(ev, case["lower"], case["upper"], cert):
                raise AssertionError("certificate replay failed")
            counts["chain_optima"] += 1
            counts["flow_replays"] += 1
            account(2)
            certificates.append({"id": case["id"], "certificate": cert})
            bad = copy.deepcopy(cert)
            bad["objective"] += 1
            if oracle.replay_flow(ev, case["lower"], case["upper"], bad):
                raise AssertionError("mutated certificate accepted")
            counts["certificate_mutations_rejected"] += 1
            account(1)
            rows.append({"id": case["id"], "kind": kind,
                         "objective": best, "cut": cert["cut"]})
        elif kind == "fork-hardness":
            account((1 << n) + (1 << case["graph_n"]))
            best, _ = oracle.optimum(ev, case["lower"], case["upper"])
            alpha = independent_number(case["graph_n"], case["graph_edges"])
            if best != alpha:
                raise AssertionError("independent-set reduction mismatch")
            counts["hardness_reduction_instances"] += 1
            rows.append({"id": case["id"], "kind": kind,
                         "objective": best, "independent_number": alpha})
        else:
            raise ValueError("unknown case kind")

    controls = {}
    ev = [event("a", "A"), event("r", "A", ["a"]),
          event("b", "B", ["r"])]
    r = Roster(ev)
    controls["separate_signer_feasibility"] = {
        "correct_accepts": r.window(0, r.all, {"A": "a", "B": "b"}) is not None,
        "mutant_accepts": all(r.window(0, r.all, {i: e}) is not None
                              for i, e in {"A": "a", "B": "b"}.items()),
    }
    ev = [event("a", "A"), event("r", "A", ["a"])]
    r = Roster(ev)
    controls["omit_verifier_floor"] = {
        "correct_accepts": r.window(r.all, r.all, {"A": "a"}) is not None,
        "mutant_accepts": r.window(0, r.all, {"A": "a"}) is not None,
    }
    ev = [event("g", "A", active=False), event("x", "A", ["g"]),
          event("y", "A", ["g"])]
    r = Roster(ev)
    controls["choose_arbitrary_fork_winner"] = {
        "correct_accepts": r.authorized(r.all, {"A": "y"}),
        "mutant_accepts": max(e["id"] for e in ev if e["active"]) == "y",
    }
    ev = [event("a", "A", key="same"),
          event("r", "A", ["a"], key="same")]
    r = Roster(ev)
    controls["identify_version_by_public_key_only"] = {
        "correct_accepts": r.authorized(r.all, {"A": "a"}),
        "mutant_accepts": ev[0]["key"] == ev[1]["key"],
    }
    if any(x != {"correct_accepts": False, "mutant_accepts": True}
           for x in controls.values()):
        raise AssertionError("negative control did not discriminate")
    account(len(controls))
    counts["negative_controls"] = len(controls)

    session_mutations = session_controls()
    account(len(session_mutations))
    counts["session_binding_mutations_rejected"] = len(session_mutations)
    counts["cases"] = len(cases)
    counts["counted_obligations_upper_bound"] = total_obligations
    return {
        "seed": SEED,
        "counts": dict(sorted(counts.items())),
        "kinds": dict(sorted(kinds.items())),
        "maximum_dimensions": max_dim,
        "negative_controls": controls,
        "session_mutations": session_mutations,
        "results": rows,
        "flow_certificates": certificates,
    }


def csv_bytes(result):
    import io
    out = io.StringIO(newline="")
    fields = ["id", "kind", "feasible", "valid_cuts", "universal",
              "objective", "independent_number", "window_or_cut"]
    writer = csv.DictWriter(out, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in result["results"]:
        writer.writerow({
            "id": row["id"],
            "kind": row["kind"],
            "feasible": row.get("feasible", ""),
            "valid_cuts": row.get("valid_cuts", ""),
            "universal": row.get("universal", ""),
            "objective": row.get("objective", ""),
            "independent_number": row.get("independent_number", ""),
            "window_or_cut": canonical(row.get("window", row.get("cut", ""))),
        })
    return out.getvalue().encode("utf-8")


def main():
    print(
        "WARNING: this campaign is permanently noncompliant; this run is "
        "post-hoc source inspection only and cannot create claim evidence.",
        file=sys.stderr,
    )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true",
                        help="write the frozen input and expected semantic result")
    parser.add_argument("--output", type=Path,
                        help="optional directory for this run's result and metrics")
    parser.add_argument("--campaign-ledger", type=Path, required=True,
                        help="durable cumulative reservation ledger")
    parser.add_argument("--campaign-label", required=True,
                        help="unique label for this invocation")
    args = parser.parse_args()

    ceiling = 3 * 1024 ** 3
    old = resource.getrlimit(resource.RLIMIT_AS)
    hard = old[1]
    resource.setrlimit(resource.RLIMIT_AS,
                       (min(ceiling, hard) if hard >= 0 else ceiling, hard))

    all_cases = generate()
    reservation = reservation_bound(all_cases)
    reservation_index = reserve(args.campaign_ledger, args.campaign_label,
                                reservation)
    begin = resource.getrusage(resource.RUSAGE_SELF)
    wall = time.monotonic()
    try:
        raw = ROOT / "data" / "cases.jsonl"
        generated_input = "".join(canonical(c) + "\n" for c in all_cases)
        if args.record:
            raw.parent.mkdir(exist_ok=True)
            raw.write_text(generated_input, encoding="utf-8")
        elif raw.read_text(encoding="utf-8") != generated_input:
            raise AssertionError("retained input disagrees with deterministic selection")

        result = study(all_cases)
        semantic = ROOT / "results" / "semantic.json"
        encoded = json.dumps(result, sort_keys=True, indent=2) + "\n"
        outcomes = csv_bytes(result)
        outcome_path = ROOT / "results" / "case-outcomes.csv"
        if args.record:
            semantic.parent.mkdir(exist_ok=True)
            semantic.write_text(encoded, encoding="utf-8")
            outcome_path.write_bytes(outcomes)
        else:
            if semantic.read_text(encoding="utf-8") != encoded:
                raise AssertionError("semantic reproduction differs from retained evidence")
            if outcome_path.read_bytes() != outcomes:
                raise AssertionError("case-outcome CSV differs from retained evidence")

        end = resource.getrusage(resource.RUSAGE_SELF)
        metrics = {
            "wall_seconds": time.monotonic() - wall,
            "user_cpu_seconds": end.ru_utime - begin.ru_utime,
            "system_cpu_seconds": end.ru_stime - begin.ru_stime,
            "peak_rss_kib": end.ru_maxrss,
            "workers": 1,
            "child_processes": 0,
            "operation": "record" if args.record else "verify",
            "reserved_obligations": reservation,
            "actual_counted_obligations": result["counts"]["counted_obligations_upper_bound"],
            "result": "all assertions passed",
        }
        finish_reservation(args.campaign_ledger, reservation_index, "passed",
                           result["counts"]["counted_obligations_upper_bound"], metrics)
        if args.output:
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / "semantic.json").write_text(encoded, encoding="utf-8")
            _atomic_json(args.output / "resources.json", metrics)
        print(json.dumps({
            "counts": result["counts"],
            "kinds": result["kinds"],
            "maximum_dimensions": result["maximum_dimensions"],
            "metrics": metrics,
        }, indent=2, sort_keys=True))
    except BaseException as exc:
        end = resource.getrusage(resource.RUSAGE_SELF)
        failed_metrics = {
            "wall_seconds": time.monotonic() - wall,
            "user_cpu_seconds": end.ru_utime - begin.ru_utime,
            "system_cpu_seconds": end.ru_stime - begin.ru_stime,
            "peak_rss_kib": end.ru_maxrss,
            "workers": 1,
            "child_processes": 0,
            "operation": "record" if args.record else "verify",
            "reserved_obligations": reservation,
            "result": "failed",
        }
        finish_reservation(args.campaign_ledger, reservation_index, "failed",
                           None, failed_metrics,
                           f"{type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    main()
