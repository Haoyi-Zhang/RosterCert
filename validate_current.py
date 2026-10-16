#!/usr/bin/env python3
"""Prospectively budgeted validation of current finite roster semantics.

This independently authorized activity does not rerun or rehabilitate the old
campaign, recover its missing codec, or establish cryptographic security.
Plan first, then execute exactly that frozen input and source snapshot once.
"""
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import argparse, json, os, platform, shutil, sys
import tempfile

ROOT = Path(__file__).resolve().parent
CEILING = 100_000
SOURCES = ('src/cases.py','src/roster.py','src/oracle.py','src/wire_profile.py','validate_current.py','LICENSE')

def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n', encoding='utf-8')

def reserve(used, amount, ceiling):
    if type(amount) is not int or amount < 0 or used + amount > ceiling:
        raise ValueError('validation budget exceeded before enumeration')
    return used + amount

def start_once(output, environment):
    # Exclusive creation closes the simultaneous-start race as well as normal
    # sequential restarts. The marker remains after failure: no resume/reset.
    with (output/'started.json').open('x',encoding='utf-8') as handle:
        json.dump(environment,handle,indent=2,sort_keys=True)
        handle.write('\n')

def plan(output):
    sys.path.insert(0, str(ROOT/'src'))
    from cases import generate
    groups = {}
    for case in generate(): groups.setdefault(case['kind'],[]).append(case)
    selected = []
    for kind, rows in groups.items():
        if kind == 'sampled-window': selected += rows[::12]
        elif kind == 'chain-optimization': selected += rows[::15]
        elif kind == 'fork-hardness': selected += rows
        else: selected += [rows[i] for i in (0,1,99,199)]
    # Each subset candidate and both per-cut decisions are charged, whether or
    # not the subset is a cut. Four further slots cover window/universal and,
    # on chain inputs, optimization and independent flow checking.
    bounds = [{'id':c['id'],'maximum_obligations':3*(1<<len(c['events']))+4} for c in selected]
    maximum = sum(c['maximum_obligations'] for c in bounds)
    reserve(0,maximum,CEILING)
    output.mkdir(parents=True, exist_ok=False)
    for name in SOURCES:
        dest=output/'source'/name; dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/name,dest)
    dump(output/'inputs.json',selected)
    dump(output/'plan.json',{
        'created_utc':datetime.now(timezone.utc).isoformat(),
        'authorization':'Main-chat human authorization on 2026-10-16 for independent current-source validation; retain old record',
        'ceiling':CEILING,'maximum_obligations':maximum,'cases':bounds,
        'input_instances':selected,
        'selection':'Every 12th sampled window; every 15th chain; all graph fixtures; positions 0,1,99,199 from each boundary family',
        'unit':'candidate subset plus two per-cut decision slots and four case-decision slots; conservative charge',
        'execution_policy':'one execution into this newly created directory; no resume or counter reset',
        'historical_campaign':'unchanged and permanently noncompliant',
    })
    print(json.dumps({'planned_cases':len(selected),'maximum_obligations':maximum,'ceiling':CEILING}))

def execute(output):
    p=json.loads((output/'plan.json').read_text())
    inputs=json.loads((output/'inputs.json').read_text())
    if p['ceiling'] != CEILING: raise ValueError('ceiling differs from source')
    if (output/'started.json').exists(): raise FileExistsError('activity already started; no reset or resume')
    for name in SOURCES:
        if (output/'source'/name).read_bytes() != (ROOT/name).read_bytes():
            raise ValueError('source changed after plan: '+name)
    assert [c['id'] for c in inputs] == [c['id'] for c in p['cases']]
    assert inputs == p['input_instances'], 'input bytes differ from the declared plan'
    maximum=sum(3*(1<<len(c['events']))+4 for c in inputs)
    assert maximum==p['maximum_obligations']
    reserve(0,maximum,CEILING)
    start_once(output,{'utc':datetime.now(timezone.utc).isoformat(),'python':sys.version,'platform':platform.platform(),'workers':1,'executable':sys.executable})
    # Run only the frozen source files, not imports from a subsequently edited tree.
    sys.path.insert(0,str(output/'source/src'))
    from roster import Roster
    import oracle
    rows=[]; charged=0; actual=Counter()
    for case,bound in zip(inputs,p['cases']):
        amount=3*(1<<len(case['events']))+4
        assert bound['maximum_obligations']==amount
        charged=reserve(charged,amount,CEILING)
        dump(output/'accounting.json',{'ceiling':CEILING,'charged_obligations':charged,'reserved_before_case':case['id'],'status':'in_progress'})
        events=case['events']; model=Roster(events)
        cuts=oracle.ideals(events); reach=oracle.ancestors(events)
        inside=[]; good=[]
        for cut in cuts:
            expected=oracle.state(events,cut,reach)
            assert model.current(model.mask(cut))==expected, case['id']
            permitted=all(expected.get(i)==e for i,e in case['profile'].items())
            assert model.authorized(model.mask(cut),case['profile'])==permitted,case['id']
            actual['current_state']+=1; actual['authorization']+=1
            if set(case['lower'])<=cut<=set(case['upper']):
                inside.append(cut)
                if permitted: good.append(cut)
        lo=model.mask(case['lower']); hi=model.mask(case['upper'])
        got=model.window(lo,hi,case['profile'])
        represented=[] if got is None else [c for c in cuts if set(model.names(got[0]))<=c<=set(model.names(got[1]))]
        assert set(represented)==set(good),case['id']
        assert model.universal(lo,hi,case['profile'])==(set(good)==set(inside)),case['id']
        actual['window']+=1; actual['universal']+=1
        row={'id':case['id'],'kind':case['kind'],'cuts':len(cuts),'inside':len(inside),'authorized_cuts':len(good)}
        if case['kind']=='chain-optimization':
            expected,_=oracle.optimum(events,case['lower'],case['upper'])
            certificate=model.optimize_chain(lo,hi)
            assert certificate['objective']==expected,case['id']
            assert oracle.replay_flow(events,case['lower'],case['upper'],certificate),case['id']
            row['flow_certificate']=certificate
            actual['optimum']+=1; actual['flow_replay']+=1
        rows.append(row)
    dump(output/'outcomes.json',rows)
    dump(output/'accounting.json',{'ceiling':CEILING,'charged_obligations':charged,'maximum_obligations':maximum,'status':'completed'})
    report={'status':'passed','cases':len(rows),'families':dict(Counter(c['kind'] for c in inputs)),
            'charged_obligations':charged,'ceiling':CEILING,'actual_decision_checks':dict(actual),
            'scope':'finite roster/window/chain-flow implementation agreement, not primitive security or general theorem proof',
            'historical_campaign':'unchanged; its missing early helper was not reconstructed'}
    dump(output/'validation.json',report); print(json.dumps(report))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('plan','execute','self-test'))
    parser.add_argument('--out',type=Path)
    args=parser.parse_args()
    if args.action=='self-test':
        assert reserve(99999,1,CEILING)==CEILING
        for used,amount in ((CEILING,1),(0,-1),(0,True)):
            try: reserve(used,amount,CEILING)
            except ValueError: pass
            else: raise AssertionError('invalid reservation accepted')
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);start_once(folder,{'test':'first'})
            try:start_once(folder,{'test':'second'})
            except FileExistsError:pass
            else:raise AssertionError('duplicate start accepted')
            assert json.loads((folder/'started.json').read_text())=={'test':'first'}
        print('budget boundary checks passed'); return 0
    if args.out is None: parser.error('--out is required')
    output=args.out.resolve()
    if output==ROOT or ROOT in output.parents:
        parser.error('use a new output directory outside the delivered artifact')
    if args.action=='plan': plan(output)
    else: execute(output)
    return 0

if __name__=='__main__': raise SystemExit(main())
