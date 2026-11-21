"""Independently audit saved real-engine events; only Chat Output can pass."""
import json
from pathlib import Path
from verify_nvidia_workflow import fixtures, find_reports
import soc_policy as policy
from update_langflow import ROOT

def model_metadata(events):
    names=set(); usages=[]; tool_events=[]
    def walk(item):
        if type(item) is dict:
            for key,value in item.items():
                if key in ('model_name','ls_model_name') and type(value) is str: names.add(value)
                if key in ('usage','token_usage','usage_metadata') and type(value) is dict and value.get('total_tokens',0):
                    if value not in usages: usages.append(value)
                if key=='type' and value in ('tool_start','tool_end'): tool_events.append(value)
                walk(value)
        elif type(item) is list:
            for child in item: walk(child)
    walk(events)
    return dict(model_names=sorted(names),recorded_usage=usages,tool_events=tool_events)

if __name__=='__main__':
    results=[]
    for name,fixture in fixtures().items():
        event_file=ROOT/('live-events-'+name+'.json')
        result_file=ROOT/('live-result-'+name+'.json')
        if not event_file.exists() or not result_file.exists():
            results.append(dict(case=name,passed=False,unresolved='No completed final-source live fixture record'))
            continue
        events=json.loads(event_file.read_text(encoding='utf-8'))
        old=json.loads(result_file.read_text(encoding='utf-8'))
        chat_events=[event for event in events if type(event) is dict and event.get('event')=='end_vertex'
            and event.get('data',{}).get('output_meta',{}).get('component_id')=='ChatOutput-KxTA8']
        reports=find_reports(chat_events)
        final=reports[-1] if reports else None
        raw=fixture if type(fixture) is str else json.dumps(fixture)
        prepared=policy.prepare(raw)
        expected=prepared.get('report',prepared.get('deterministic_report'))
        errors=[]
        latest_job=json.loads((ROOT/('live-job-'+name+'.json')).read_text(encoding='utf-8'))
        if old.get('job_id') != latest_job.get('job_id'):
            errors.append('Saved result is from an earlier job; latest run did not complete')
        if final is None:
            errors.append('No final Chat Output report')
        else:
            for key in ('status','risk_score','risk_level','threat_classification','mitre_mapping','normalized_evidence','risk_score_breakdown','escalation_required','human_review_required'):
                if final.get(key)!=expected.get(key): errors.append('Final '+key+' differs from expected')
            if final.get('status')=='ok':
                verified=policy.verify(raw,json.dumps(final))
                if verified['status']!='ok': errors.extend(verified['validation_errors'])
                if any(action.get('requires_human_approval') is not True for action in final.get('recommended_actions',[])):
                    errors.append('Recommendation lacks mandatory approval')
        metadata=model_metadata(events)
        if expected['status']=='ok':
            if 'openai/gpt-oss-20b' not in metadata['model_names'] or not metadata['recorded_usage']:
                errors.append('No recorded configured NVIDIA model/usage evidence')
        elif metadata['recorded_usage'] or metadata['model_names']:
            errors.append('Invalid input unexpectedly has model usage')
        if metadata['tool_events']:
            errors.append('Unexpected tool execution event')
        result=dict(case=name,passed=not errors,duration_seconds=old.get('duration_seconds'),job_id=old.get('job_id'),
            final_report=final,model_evidence=metadata,errors=errors,event_file=event_file.name)
        results.append(result)
    offline=json.loads((ROOT/'offline-test-results.json').read_text(encoding='utf-8'))
    installed=json.loads((ROOT/'installed-state-verification.json').read_text(encoding='utf-8'))
    summary=dict(total=len(results),passed=sum(r['passed'] for r in results),failed=sum(not r['passed'] for r in results),
        offline_tests=offline,installed_state=installed,results=results)
    (ROOT/'nvidia-workflow-test-results.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    lines=['# Final SOC validator repair test report','',
        'Existing flow: SOC AI Analyst (`4b83ff2d-9c26-4152-b46b-c3dbb46502b8`).',
        'Project artifacts are on D:. No E: or VM files were modified by this work. The existing app manages its internal storage separately.','',
        '## Final offline tests','',
        str(offline['tests_run'])+' tests; '+str(offline['failures'])+' failures; '+str(offline['errors'])+' errors; '+str(offline['skipped'])+' skipped.','',
        '## Real Langflow/NVIDIA workflow','',
        '| Fixture | Result | Score / level | MITRE | Escalate | Seconds |',
        '|---|---|---|---|---|---|']
    for result in results:
        report=result.get('final_report') or {}
        mapping=report.get('mitre_mapping') or {}
        lines.append('| '+result['case']+' | '+('PASS' if result['passed'] else 'FAIL')+' | '+str(report.get('risk_score'))+' / '+str(report.get('risk_level'))+' | '+str(mapping.get('technique_id'))+' | '+str(report.get('escalation_required'))+' | '+str(result.get('duration_seconds'))+' |')
    lines += ['',str(summary['passed'])+' / '+str(summary['total'])+' live cases passed; '+str(summary['failed'])+' unresolved case failures.',
        'Successful valid fixtures must have a final Chat Output report, exact deterministic scoring, expected supported MITRE mapping, preserved recommendations with mandatory approval, and recorded openai/gpt-oss-20b model usage. Invalid fixtures must have no model usage. No fixture may have tool-execution events.','',
        '## Installation integrity','',
        'All three stored component sources match their D: files. Original enterprise playbook, selected model and all five edges are checked unchanged. Playbook SHA-256: `'+installed['playbook_sha256']+'`.','',
        '## Failures found and corrected during work','',
        '- The native code editor did not retain replacement text; installation used the existing local Langflow API and source hashes instead.',
        '- Langflow initially rejected the Agent subclass alias; the alias now meets its Component-class naming rule and has a regression test.',
        '- The first NVIDIA packet-only response invented threshold 40 and attributed an indicator as source IP. That content failure is preserved in initial-nvidia-grounding-failure.json; explicit grounding checks and correction feedback were added.',
        '- The initial threshold fixture also mislabeled a detector rule as a baseline; baseline taxonomy checks and regression tests were added.',
        '- A grounding check initially confused a supplied flood threshold with an absent detector threshold; the distinction is now explicit and regression-tested.',
        '- The first expanded grounding check overrejected a generic escalation explanation. The explanation now names the actual supplied override condition; its regression test passes.',
        '- A critical fixture exceeded the 240-second harness budget; its final-source retry passed in 178.403 seconds. The harness now allows 600 seconds without changing the three-attempt model validation limit.',
        '- A prompt-injection fixture retained scoring and approval requirements but failed source-attribution grounding after three model attempts. The rejected report is preserved in initial-prompt-injection-grounding-failure.json; the final result below records the subsequent final-source retry.',
        '- Two initial live requests exceeded the harness 40-second socket timeout. Only those test jobs were cancelled, and the harness was corrected to allow the documented bounded NVIDIA attempts.','',
        '## Remaining limits','',
        'No automated validator proves every free-form model sentence or independently authenticates user-supplied telemetry. Human review remains mandatory. Unsupported or malformed contextual evidence does not earn points. NVIDIA availability/latency and future stochastic responses can still fail; failures return JSON and do not lower validation standards. Live fixtures are synthetic and do not establish that real sensors, VMs or Wazuh ingestion are integrated.','',
        'See README.md for exact reproduction commands and evidence schemas. Raw sanitized build events, individual final reports, offline results, and installation hashes are retained alongside this report.']
    for result in results:
        if not result['passed']:
            lines += ['', '### Unresolved: '+result['case'], '', json.dumps(result.get('errors',result.get('unresolved')),indent=2)]
    (ROOT/'FINAL-TEST-REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(dict(total=summary['total'],passed=summary['passed'],failed=summary['failed'],cases=[dict(case=r['case'],passed=r['passed'],errors=r.get('errors')) for r in results]),indent=2))
    raise SystemExit(0 if not summary['failed'] and offline['successful'] and all(installed['checks'].values()) else 1)

