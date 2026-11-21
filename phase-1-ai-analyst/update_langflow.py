"""Update only existing component source using the running local Langflow API.
Uses desktop auto-login in memory; never writes credentials or creates API keys.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import urllib.request

ROOT=Path(__file__).resolve().parent
BASE=os.environ.get('LANGFLOW_URL', 'http://127.0.0.1:7860')
FLOW=os.environ.get('SOC_FLOW_ID', '4b83ff2d-9c26-4152-b46b-c3dbb46502b8')  # set to your own flow's ID

def api(path, body=None, token=None, method=None, timeout=30):
    headers={'Content-Type':'application/json'}
    if token: headers['Authorization']='Bearer '+token
    request=urllib.request.Request(BASE+path,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method)
    with urllib.request.urlopen(request,timeout=timeout) as response:
        payload=response.read().decode('utf-8')
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        if '/events' not in path: raise
        events=[]
        for line in payload.splitlines():
            line=line.strip()
            if line.startswith('data:'): line=line[5:].strip()
            if not line or line.startswith(':') or line.startswith('event:'): continue
            try: events.append(json.loads(line))
            except json.JSONDecodeError: continue
        return events

def sanitize(value):
    if type(value) is list: return [sanitize(child) for child in value]
    if type(value) is dict:
        result={}
        for key,child in value.items():
            if any(word in key.lower() for word in ('api_key','password','access_token','refresh_token','secret')):
                if type(child) is dict:
                    child=copy.deepcopy(child)
                    if 'value' in child: child['value']=''
                    result[key]=child
                else: result[key]='[REDACTED]' if child else child
            else: result[key]=sanitize(child)
        return result
    return value

def digest(value): return hashlib.sha256(value.encode()).hexdigest()

if __name__=='__main__':
    token=api('/api/v1/auto_login')['access_token']
    before=api('/api/v1/flows/'+FLOW,token=token)
    nodes={node['id']:node for node in before['data']['nodes']}
    agent=nodes['Agent-EXpSZ']
    prompt=agent['data']['node']['template']['system_prompt']['value']
    backup=ROOT/'backup-before-validator-repair'
    snapshot=backup/'flow-original-sanitized.json'
    if not snapshot.exists(): snapshot.write_text(json.dumps(sanitize(before),indent=2),encoding='utf-8')
    playbook=ROOT/'enterprise-soc-playbook-v1.0.md'
    if not playbook.exists(): playbook.write_text(prompt,encoding='utf-8')
    sources={'CustomComponent-Zs0Za':'soc_input_validation.py','CustomComponent-1z4df':'soc_output_review_gate.py','Agent-EXpSZ':'soc_agent_guard.py'}
    patch=copy.deepcopy(before['data'])
    for node in patch['nodes']:
        if node['id'] in sources:
            node['data']['node']['template']['code']['value']=(ROOT/sources[node['id']]).read_text(encoding='utf-8-sig')
            descriptions={'CustomComponent-Zs0Za':'Strict JSON, complete 0-100 playbook scoring and invalid-input JSON transport.', 'CustomComponent-1z4df':'Checks evidence, scoring, MITRE and human approval; preserves advisory NVIDIA analysis and investigation recommendations.', 'Agent-EXpSZ':'Enterprise SOC NVIDIA analysis with invalid-input bypass, no tools or history, and bounded validation correction.'}
            node['data']['node']['description']=descriptions[node['id']]
            node['data']['node']['edited']=True
    api('/api/v1/flows/'+FLOW,body={'data':patch},token=token,method='PATCH')
    after=api('/api/v1/flows/'+FLOW,token=token)
    updated={node['id']:node for node in after['data']['nodes']}
    checks={filename:updated[nid]['data']['node']['template']['code']['value']==(ROOT/filename).read_text(encoding='utf-8-sig') for nid,filename in sources.items()}
    checks['playbook_unchanged']=updated['Agent-EXpSZ']['data']['node']['template']['system_prompt']['value']==prompt
    checks['model_unchanged']=updated['Agent-EXpSZ']['data']['node']['template']['model']==agent['data']['node']['template']['model']
    checks['wiring_unchanged']=after['data']['edges']==before['data']['edges']
    result=dict(flow_id=FLOW,flow_name=after['name'],checks=checks,playbook_sha256=digest(prompt),
        component_sha256={filename:digest(updated[nid]['data']['node']['template']['code']['value']) for nid,filename in sources.items()})
    (ROOT/'installed-state-verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))
    if not all(checks.values()): raise SystemExit(1)
