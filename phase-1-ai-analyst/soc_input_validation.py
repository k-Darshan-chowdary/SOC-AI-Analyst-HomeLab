"""SOC playbook policy v2: pure validation/scoring; no network or system actions."""
import copy
import ipaddress
import json
import math
from datetime import datetime, timezone

CONDITIONS = ('packet_volume', 'repeated_activity', 'privileged_service', 'icmp_flood', 'authentication')
MAPPINGS = {
    'T1110': ('Credential Access', 'Brute Force'),
    'T1046': ('Discovery', 'Network Service Discovery'),
    'T1071': ('Command and Control', 'Application Layer Protocol'),
    'T1498': ('Impact', 'Network Denial of Service'),
}
CLASSES = ('Brute Force Attempt', 'Network Reconnaissance / Scanning', 'Suspicious Network Volume', 'Possible Malware Communication', 'Benign Network Noise', 'Unknown')

class InvalidAlert(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__('; '.join(errors))

def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key: ' + key)
            result[key] = value
        return result
    def bad(value):
        raise ValueError('Nonfinite JSON number: ' + value)
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=bad)
    if type(value) is not dict:
        raise ValueError('Expected one JSON object')
    def finite(item):
        if type(item) is float and not math.isfinite(item):
            raise ValueError('Nonfinite JSON number')
        if type(item) is dict:
            for child in item.values():
                finite(child)
        elif type(item) is list:
            for child in item:
                finite(child)
    finite(value)
    return value

def number(value, minimum=0, positive=False):
    return type(value) in (int, float) and math.isfinite(value) and (value > minimum if positive else value >= minimum)

def text(value):
    return type(value) is str and bool(value.strip())

def timestamp(value):
    if number(value):
        return float(value)
    if not text(value):
        raise ValueError('Timestamp must be UTC/offset ISO 8601 or epoch seconds')
    d = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if d.tzinfo is None:
        raise ValueError('Timestamp requires timezone')
    return d.timestamp()

def failure(status, reasons):
    errors = redact(reasons if type(reasons) is list else [str(reasons)])
    return dict(status=status, validation_errors=errors, alert_id=None, alert_type=None,
        threat_classification=None, risk_score=None, risk_level=None, confidence_level=None,
        normalized_evidence=None, risk_score_breakdown=[],
        mitre_mapping=dict(tactic=None, technique_id=None, technique_name=None),
        analysis_reasoning=None, false_positive_considerations=[], missing_evidence=[],
        recommended_actions=[], escalation_required=False, escalation_reason=None,
        human_review_required=True, executive_summary='Processing stopped. Human review is required.')

def redact(value):
    import re
    if type(value) is dict:
        return {key: ('[REDACTED]' if re.search(r'(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie)', key) else redact(child)) for key, child in value.items()}
    if type(value) is list:
        return [redact(child) for child in value]
    if type(value) is str:
        value = re.sub(r'(?i)\b(?:nvapi-|sk-)[A-Za-z0-9_-]{8,}', '[REDACTED]', value)
        value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9_.-]+', 'Bearer [REDACTED]', value)
        value = re.sub(r'(?i)\b(password|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*[^\s,;]+', r'\1=[REDACTED]', value)
    return value

def normalize(raw):
    a = redact(strict_json(raw))
    errors = []
    for key in ('alert_id', 'alert_type', 'indicator_type', 'indicator_value', 'protocol'):
        if not text(a.get(key)):
            errors.append(key + ': nonempty string required')
        else:
            a[key] = a[key].strip()
    for key in ('source_host', 'destination_host'):
        if key not in a or (a[key] is not None and type(a[key]) is not str):
            errors.append(key + ': string or null required')
    for key in ('destination_ip', 'source_ip'):
        if key == 'destination_ip' and key not in a:
            errors.append(key + ': required; null allowed')
        if a.get(key) is not None:
            try:
                if type(a[key]) is not str:
                    raise ValueError()
                a[key] = str(ipaddress.ip_address(a[key].strip()))
            except ValueError:
                errors.append(key + ': invalid IP address')
    if text(a.get('indicator_type')) and a['indicator_type'].lower() == 'ip':
        a['indicator_type'] = 'ip'
        try:
            a['indicator_value'] = str(ipaddress.ip_address(a.get('indicator_value', '')))
        except ValueError:
            errors.append('indicator_value: invalid IP address')
    e = a.get('evidence')
    if type(e) is not dict:
        errors.append('evidence: object required')
        e = {}
    if type(e.get('packet_count')) is not int or e['packet_count'] < 0:
        errors.append('evidence.packet_count: nonnegative integer required; boolean forbidden')
    if not number(e.get('time_window_seconds'), positive=True):
        errors.append('evidence.time_window_seconds: positive finite number required; boolean forbidden')
    # Untrusted alerts cannot inject validator transport/control fields.
    if any(key.startswith('_soc_') for key in a):
        errors.append('Reserved _soc_ transport field in original alert')
    optional = ('detection_threshold', 'repeated_events', 'related_alerts', 'service_context',
        'asset_criticality', 'documented_flood_threshold', 'historical_baseline',
        'authentication_events', 'connection_attempts', 'system_impact', 'authorized_test',
        'c2_evidence', 'confirmed_compromise', 'wazuh_rule_id', 'wazuh_rule_level')
    for key in optional:
        if key in a and key in e and a[key] != e[key]:
            errors.append('Conflicting ' + key + ' at alert and evidence levels')
    threshold = a.get('detection_threshold', e.get('detection_threshold'))
    if threshold is not None and not number(threshold):
        errors.append('detection_threshold: nonnegative finite number required')
    for key in ('source_port', 'destination_port'):
        value = a.get(key, e.get(key))
        if value is not None and (type(value) is not int or not 0 <= value <= 65535):
            errors.append(key + ': integer port 0..65535 required')
    if errors:
        raise InvalidAlert(errors)
    a['protocol'] = a['protocol'].upper()
    return a

def evaluate(a):
    e = a['evidence']
    errors = []
    def get(key):
        return a.get(key, e.get(key))
    def obj(key):
        value = get(key)
        if value is None:
            return {}
        if type(value) is not dict:
            errors.append(key + ': structured evidence object required; labels alone do not qualify')
            return {}
        return value
    def rows(key):
        value = get(key)
        if value is None:
            return []
        if type(value) is not list or any(type(row) is not dict for row in value):
            errors.append(key + ': array of telemetry objects required')
            return []
        return value
    def sourced(item):
        return text(item.get('source')) and text(item.get('reference'))
    def same_subject(item):
        # No automatic promotion of indicator_value to source_ip.
        if item.get('indicator_value') == a['indicator_value']:
            return True
        return a.get('source_ip') is not None and item.get('source_ip') == a['source_ip']
    n, seconds = e['packet_count'], e['time_window_seconds']
    try:
        rate = n / seconds
        if not math.isfinite(rate):
            raise OverflowError()
    except (OverflowError, ZeroDivisionError):
        raise InvalidAlert(['Calculated packet rate exceeds finite numeric range'])
    repeat_rows = rows('repeated_events') + rows('related_alerts')
    timed = []
    for row in repeat_rows:
        if 'timestamp' in row:
            try:
                stamp = timestamp(row['timestamp'])
            except (ValueError, OverflowError):
                errors.append('repeated/related event: invalid timestamp')
                continue
            ident = row.get('event_id', row.get('alert_id'))
            if sourced(row) and same_subject(row) and text(ident):
                timed.append((stamp, ident, row))
    repeated_pair = next(((left, right) for i, left in enumerate(timed) for right in timed[i+1:]
        if left[1] != right[1] and 0 <= abs(left[0]-right[0]) < 60), None)
    service = obj('service_context')
    asset = obj('asset_criticality')
    for label, value in (('service_context', service), ('asset_criticality', asset)):
        for flag in ('targeted', 'privileged', 'sensitive_management'):
            if flag in value and type(value[flag]) is not bool:
                errors.append(label + '.' + flag + ': boolean required')
    privileged = next((item for item in (service, asset) if sourced(item) and same_subject(item)
        and item.get('targeted') is True and (item.get('privileged') is True or item.get('sensitive_management') is True)
        and text(item.get('service_name'))), None)
    auth_rows = rows('authentication_events')
    suspicious_auth = []
    seen_auth = set()
    for row in auth_rows:
        # Each observed failure must be explicitly credential-related, not a title or arbitrary label.
        if (sourced(row) and same_subject(row) and row.get('outcome') == 'failure'
            and text(row.get('account')) and text(row.get('service_name')) and text(row.get('event_id'))
            and row['event_id'] not in seen_auth):
            suspicious_auth.append(row)
            seen_auth.add(row['event_id'])
    authentication = len(suspicious_auth) >= 2
    attempts = rows('connection_attempts')
    probes = [row for row in attempts if sourced(row) and same_subject(row)
        and row.get('probe') is True and type(row.get('destination_port')) is int
        and 0 <= row['destination_port'] <= 65535 and text(row.get('destination_ip'))]
    for row in probes:
        try:
            ipaddress.ip_address(row['destination_ip'])
        except ValueError:
            errors.append('connection_attempts.destination_ip: invalid IP address')
    scanning = len({(row['destination_ip'], row['destination_port']) for row in probes}) >= 2
    flood = obj('documented_flood_threshold')
    baseline = obj('historical_baseline')
    impact = obj('system_impact')
    compromise = obj('confirmed_compromise')
    benign = obj('authorized_test')
    c2 = obj('c2_evidence')
    for label, value in (('documented_flood_threshold', flood), ('historical_baseline', baseline)):
        if 'value' in value and not number(value['value']):
            errors.append(label + '.value: nonnegative finite number required')
        if 'packets_per_second' in value and not number(value['packets_per_second']):
            errors.append(label + '.packets_per_second: nonnegative finite number required')
    threshold_flood = False
    if sourced(flood) and same_subject(flood) and number(flood.get('value')):
        if flood.get('unit') == 'packets_per_second':
            threshold_flood = rate > flood['value']
        elif flood.get('unit') == 'packets_per_window' and flood.get('time_window_seconds') == seconds:
            threshold_flood = n > flood['value']
    abnormal = (sourced(baseline) and same_subject(baseline) and number(baseline.get('packets_per_second'))
        and number(baseline.get('abnormal_threshold_pps'), positive=True)
        and baseline['abnormal_threshold_pps'] >= baseline['packets_per_second']
        and rate > baseline['abnormal_threshold_pps'])
    sustained = abnormal and baseline.get('sustained') is True
    availability = (sourced(impact) and same_subject(impact)
        and number(impact.get('availability_loss_percent'), positive=True)
        and impact['availability_loss_percent'] <= 100 and impact.get('correlated_network_traffic') is True)
    repeated_high = repeated_pair is not None and all(
        row[2].get('flood_threshold_exceeded') is True and text(row[2].get('flood_threshold_reference'))
        for row in repeated_pair)
    icmp = a['protocol'] in ('ICMP', 'ICMPV6') and (threshold_flood or sustained or availability or repeated_high)
    confirmed = (sourced(compromise) and same_subject(compromise) and compromise.get('confirmed') is True
        and text(compromise.get('finding')))
    benign_supported = sourced(benign) and same_subject(benign) and benign.get('verified') is True and text(benign.get('purpose'))
    c2_supported = (sourced(c2) and same_subject(c2) and text(c2.get('application_protocol'))
        and type(c2.get('corroborating_observations')) is list
        and len({(row.get('source'), row.get('reference')) for row in c2['corroborating_observations']
            if type(row) is dict and sourced(row) and text(row.get('finding'))}) >= 2
        and c2.get('suspected_command_and_control') is True)
    if errors:
        raise InvalidAlert(errors)
    p = 0 if n <= 30 else 20 if n <= 50 else 30 if n <= 100 else 40
    points = (p, 20 if repeated_pair else 0, 20 if privileged else 0, 15 if icmp else 0, 25 if authentication else 0)
    refs = [str(n) + ' packets in ' + str(seconds) + ' seconds',
        ('Distinct events ' + repeated_pair[0][1] + ' and ' + repeated_pair[1][1] + ' are ' + str(abs(repeated_pair[0][0]-repeated_pair[1][0])) + ' seconds apart') if repeated_pair else None,
        (privileged['source'] + ': ' + privileged['reference'] + '; targeted ' + privileged['service_name']) if privileged else None,
        ('Supplied ICMP telemetry supports flood-like behavior: ' + ', '.join(label for label, flag in (
            ('documented flood threshold exceeded', threshold_flood), ('sustained supplied baseline exceedance', sustained),
            ('correlated availability loss', availability), ('corroborated repeated flood-threshold bursts', repeated_high)) if flag)) if icmp else None,
        ('Repeated authentication failures in supplied telemetry: ' + ', '.join(row['event_id'] for row in suspicious_auth)) if authentication else None]
    breakdown = [dict(condition=condition, points=score, supporting_evidence=reference or 'Not established by supplied evidence; this does not prove absence')
        for condition, score, reference in zip(CONDITIONS, points, refs)]
    score = min(100, sum(points))
    level = 'Low' if score < 30 else 'Medium' if score < 60 else 'High' if score < 80 else 'Critical'
    threshold = get('detection_threshold')
    volume = (threshold is not None and n > threshold) or abnormal or icmp or threshold_flood
    dos_supported = availability and (icmp or threshold_flood or sustained or repeated_high)
    supported = {'Unknown'}
    for label, flag in (('Brute Force Attempt', authentication), ('Network Reconnaissance / Scanning', scanning),
        ('Possible Malware Communication', c2_supported), ('Suspicious Network Volume', volume), ('Benign Network Noise', benign_supported)):
        if flag:
            supported.add(label)
    primary = next((label for label in ('Brute Force Attempt', 'Network Reconnaissance / Scanning',
        'Possible Malware Communication', 'Suspicious Network Volume', 'Benign Network Noise') if label in supported), 'Unknown')
    mitre = {'Brute Force Attempt': 'T1110', 'Network Reconnaissance / Scanning': 'T1046',
        'Possible Malware Communication': 'T1071'}.get(primary)
    if primary == 'Suspicious Network Volume' and dos_supported:
        mitre = 'T1498'
    mapping = dict(tactic=None, technique_id=None, technique_name=None)
    if mitre:
        mapping = dict(tactic=MAPPINGS[mitre][0], technique_id=mitre, technique_name=MAPPINGS[mitre][1])
    observed = {key: a.get(key) for key in ('indicator_type', 'indicator_value', 'source_host', 'destination_host', 'source_ip', 'destination_ip', 'protocol')}
    observed.update(packet_count=n, time_window_seconds=seconds, packets_per_second=round(rate, 2))
    # Preserve supplied Wazuh identifiers in the original normalized alert; never convert severity to score.
    urgency = availability or confirmed
    escalation = score >= 60 or urgency
    reason = ('Critical score requires immediate Tier 2 escalation; verify evidence.' if score >= 80
        else 'High score requires prompt analyst review and evidence correlation.' if score >= 60
        else 'Escalation override: supplied correlated network availability loss requires review.' if availability
        else 'Escalation override: independently supplied confirmation of compromise requires review.' if confirmed
        else 'Score below 60; no supplied urgency evidence establishes an escalation override.')
    report = dict(status='ok', validation_errors=[], alert_id=a['alert_id'], alert_type=a['alert_type'],
        threat_classification=primary, risk_score=score, risk_level=level, confidence_level='Low',
        normalized_evidence=observed, risk_score_breakdown=breakdown, mitre_mapping=mapping,
        analysis_reasoning='Deterministic calculations from supplied evidence. Conclusions remain subject to human verification.',
        false_positive_considerations=['Legitimate diagnostics, retries, or authorized testing are possible; verify supporting context.'],
        missing_evidence=['Independently verify telemetry provenance, authorization, and asset context.'],
        recommended_actions=[dict(priority='P1' if score >= 80 or urgency else 'P2' if escalation else 'P3',
            action='Escalate to Tier 2 immediately' if score >= 80 else 'Request prompt analyst review' if escalation else 'Review supporting telemetry',
            reason=reason, requires_human_approval=True)],
        escalation_required=escalation, escalation_reason=reason, human_review_required=True,
        executive_summary='Supplied telemetry supports a triage score of ' + str(score) + '. Human investigation is required; the score does not establish compromise.')
    flags = dict(authentication=authentication, scanning=scanning, c2=c2_supported, icmp_flood=icmp,
        availability_loss=availability, dos=dos_supported, compromise=confirmed, benign=benign_supported,
        contextual=bool(repeated_pair or privileged or authentication or scanning or c2_supported or icmp or benign_supported),
        allowed_classifications=sorted(supported))
    return report, flags

def compute(raw):
    a = normalize(raw)
    report, _ = evaluate(a)
    return a, report

def prepare(raw):
    try:
        alert, report = compute(raw)
        # Contract is generated by the trusted validator, never accepted from input.
        return dict(_soc_validated=True, alert=alert, deterministic_report=report)
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        return dict(_soc_invalid=True, report=failure('invalid_input', getattr(exc, 'errors', str(exc))))

def verify(raw, candidate_text):
    try:
        alert = normalize(raw)
        expected, flags = evaluate(alert)
    except (ValueError, TypeError, OverflowError, RecursionError) as exc:
        return failure('invalid_input', getattr(exc, 'errors', str(exc)))
    try:
        candidate = strict_json(candidate_text)
        if candidate.get('status') in ('model_error','verification_failed') and candidate == failure(candidate['status'],candidate.get('validation_errors',[])):
            return candidate
        if set(candidate) != set(expected):
            raise ValueError('Report fields do not match enterprise schema')
        def shape(value, template, path):
            if template is None:
                if value is not None:
                    raise ValueError(path + ': must be null')
            elif type(template) is dict:
                if type(value) is not dict or set(value) != set(template):
                    raise ValueError(path + ': object schema mismatch')
                for key in template:
                    shape(value[key], template[key], path + '.' + key)
            elif type(template) is list:
                if type(value) is not list:
                    raise ValueError(path + ': array required')
            elif type(template) in (int, float):
                if not number(value, minimum=-1e300):
                    raise ValueError(path + ': finite number required; booleans forbidden')
            elif type(value) is not type(template):
                raise ValueError(path + ': incorrect type')
        # Analytical mapping/classification may be conservative, but must be evidence-supported.
        template = copy.deepcopy(expected)
        template['mitre_mapping'] = dict(tactic='', technique_id='', technique_name='')
        candidate_mapping = candidate.get('mitre_mapping')
        if candidate_mapping == dict(tactic=None, technique_id=None, technique_name=None):
            template['mitre_mapping'] = candidate_mapping
        shape(candidate, template, 'report')
        for key in ('status', 'validation_errors', 'alert_id', 'alert_type', 'risk_score', 'risk_level', 'normalized_evidence',
            'risk_score_breakdown', 'escalation_required', 'human_review_required'):
            if candidate[key] != expected[key]:
                raise ValueError(key + ': mismatch with independently computed evidence')
        if type(candidate['risk_score']) is not int:
            raise ValueError('risk_score: integer required')
        if type(candidate['normalized_evidence']['packet_count']) is not int:
            raise ValueError('normalized_evidence.packet_count: integer required')
        for row in candidate['risk_score_breakdown']:
            if type(row['points']) is not int:
                raise ValueError('risk breakdown points: integer required')
        classification = candidate['threat_classification']
        if classification not in flags['allowed_classifications']:
            raise ValueError('Classification unsupported by supplied telemetry')
        # Avoid Unknown suppressing strongly observed behavior; hypotheses may still remain uncertain.
        if expected['threat_classification'] != 'Unknown' and classification == 'Unknown':
            raise ValueError('Classification omits supported primary behavior')
        mapping = candidate['mitre_mapping']
        if mapping['technique_id'] is not None:
            tid = mapping['technique_id']
            allowed = {'Brute Force Attempt': 'T1110', 'Network Reconnaissance / Scanning': 'T1046', 'Possible Malware Communication': 'T1071'}.get(classification)
            if classification == 'Suspicious Network Volume' and flags['dos']:
                allowed = 'T1498'
            if tid != allowed or tid not in MAPPINGS or (mapping['tactic'], mapping['technique_name']) != MAPPINGS[tid]:
                raise ValueError('MITRE mapping unsupported or identifier/name/tactic mismatch')
        if candidate['confidence_level'] not in ('Low', 'Medium', 'High'):
            raise ValueError('Invalid confidence_level')
        if candidate['confidence_level'] != 'Low' and not flags['contextual']:
            raise ValueError('Elevated confidence requires contextual evidence; volume alone is insufficient')
        if candidate['confidence_level'] == 'High':
            sources = set()
            def gather(value):
                if type(value) is dict:
                    if text(value.get('source')) and text(value.get('reference')):
                        sources.add(value['source'])
                    for child in value.values(): gather(child)
                elif type(value) is list:
                    for child in value: gather(child)
            gather(alert)
            if len(sources) < 2:
                raise ValueError('High confidence requires multiple consistent independent telemetry sources')
        for key in ('analysis_reasoning', 'escalation_reason', 'executive_summary'):
            if not text(candidate[key]):
                raise ValueError(key + ': nonempty explanation required')
        for key in ('false_positive_considerations', 'missing_evidence'):
            if not candidate[key] or any(not text(value) for value in candidate[key]):
                raise ValueError(key + ': nonempty string array required')
        if not candidate['recommended_actions']:
            raise ValueError('Investigation recommendations are required')
        import re
        disruptive = re.compile(r'\b(block|isolat\w*|reset|disabl\w*|terminat\w*|firewall|contain\w*)\b', re.I)
        destructive = re.compile(r'\b(delete|erase|wipe|exploit|exfiltrat\w*)\b|(?:powershell|cmd\.exe|bash\s+-c|sudo\s|rm\s+-|curl\s)|(?:launch|perform|conduct)\s+(?:an?\s+)?attack', re.I)
        for action in candidate['recommended_actions']:
            shape(action, expected['recommended_actions'][0], 'recommended_actions')
            if action['priority'] not in ('P1', 'P2', 'P3') or not text(action['action']) or not text(action['reason']):
                raise ValueError('Invalid recommendation priority/action/reason')
            if action['requires_human_approval'] is not True:
                raise ValueError('Every recommendation requires human approval')
            wording = action['action'] + ' ' + action['reason']
            if destructive.search(action['action']):
                raise ValueError('Executable, destructive, or offensive recommendation rejected')
            if disruptive.search(wording) and not (flags['authentication'] or flags['scanning'] or flags['c2'] or flags['availability_loss'] or flags['compromise']):
                raise ValueError('Disruptive containment cannot be justified by packet volume alone')
        if expected['escalation_required'] and not any(action['priority'] in ('P1', 'P2') for action in candidate['recommended_actions']):
            raise ValueError('Escalation requires immediate or prompt analyst action')
        if expected['risk_score'] >= 80 and not any(action['priority'] == 'P1' and 'tier 2' in action['action'].lower() for action in candidate['recommended_actions']):
            raise ValueError('Critical result requires immediate Tier 2 escalation recommendation')
        # Explicit playbook grounding checks for recurring model failure modes.
        narrative = ' '.join([candidate['analysis_reasoning'], candidate['executive_summary'], candidate['escalation_reason']]
            + candidate['false_positive_considerations'] + candidate['missing_evidence']
            + [action['reason'] for action in candidate['recommended_actions']])
        lower = narrative.lower()
        detector_threshold = alert.get('detection_threshold', alert['evidence'].get('detection_threshold'))
        if detector_threshold is None:
            other_threshold = alert.get('documented_flood_threshold',alert['evidence'].get('documented_flood_threshold'))
            for sentence in re.split(r'(?<=[.!?])\s+', narrative):
                explicit_detector = re.search(r'(?:detector|detection).{0,70}(?:threshold|rule)|(?:laboratory|lab).{0,40}(?:threshold|rule)|packet_count\s*>\s*40', sentence, re.I)
                unsourced_generic = not other_threshold and re.search(r'threshold.{0,50}(?:40|exceed)', sentence, re.I)
                if explicit_detector or unsourced_generic:
                    if not re.search(r'(?:not (?:supplied|provided|available|established)|no .{0,35}(?:supplied|provided|available)|absent|unknown|missing|unspecified|unavailable|without .{0,20}(?:supplied|provided))', sentence, re.I):
                        raise ValueError('Unsupported detector threshold claim: no detection_threshold was supplied; the playbook example is not telemetry')
        baseline = alert.get('historical_baseline',alert['evidence'].get('historical_baseline'))
        if not baseline:
            for sentence in re.split(r'(?<=[.!?])\s+', candidate['analysis_reasoning']+' '+candidate['executive_summary']):
                if re.search(r'baseline',sentence,re.I) and not re.search(r'not (?:supplied|provided|available|established)|no .{0,40}baseline|absent|unknown|missing|unspecified|unavailable|(?:obtain|collect|request|compare|review|verify|establish|need|necessary|would|could)',sentence,re.I):
                    raise ValueError('Unsupported baseline claim: a detector rule is not a historical traffic baseline')
                if re.search(r'\b(?:normal|typical|modest) (?:packet |traffic )?(?:rate|volume|traffic)\b',sentence,re.I) and not re.search(r'not |unknown|missing|no .{0,35}baseline|could|may|might',sentence,re.I):
                    raise ValueError('Relative traffic normality/volume claim requires supplied baseline context')
        indicator = re.escape(alert['indicator_value'])
        if alert.get('source_ip') is None:
            for sentence in re.split(r'(?<=[.!?])\s+', narrative):
                attribution = re.search(r'(?:from|source(?: IP)?(?: address)?(?: is|:)?|originat(?:ed|ing) from)\s+(?:the\s+)?(?:indicator\s+)?(?:IP\s+)?(?:address\s+)?' + indicator, sentence, re.I)
                qualified = re.search(r'(?:not|cannot|unable to).{0,45}(?:confirm|establish|attribute|determine)',sentence,re.I)
                if attribution and not qualified:
                    raise ValueError('Unsupported source attribution: indicator_value does not establish source_ip')
        for key in ('source_ip','destination_ip','protocol','packet_count','time_window_seconds'):
            known = alert.get(key,alert['evidence'].get(key))
            if known is not None:
                human_key = key.replace('_','[ _-]')
                for statement in candidate['missing_evidence']:
                    if re.search(human_key,statement,re.I) and re.search(r'not (?:supplied|provided)|missing|unavailable|unknown',statement,re.I):
                        raise ValueError('Missing-evidence claim contradicts supplied field: ' + key)
        unsupported_patterns = [
            (not flags['availability_loss'], r'(?:no|without) (?:service |network |system )?(?:disruption|impact|availability loss)(?: occurred| observed| detected| was| is|[.;])', 'Missing impact measurements cannot establish absence of impact'),
            (not flags['authentication'], r'no (?:authentication attacks|authentication failures|credential abuse)(?: occurred| observed| detected|[.;])', 'Missing authentication telemetry cannot establish a negative finding'),
            (not flags['compromise'], r'(?:confirmed|verified) (?:compromise|malware infection)|(?:endpoint|host|system) (?:is|was) compromised', 'Confirmed compromise requires independently supplied confirmation'),
        ]
        for applies, pattern, reason in unsupported_patterns:
            if applies and re.search(pattern,narrative,re.I):
                # Conditional recommendations and explicit absence of confirmation are not assertions.
                cleaned = re.sub(r'(?:not|no|without) (?:independently )?(?:confirmed|verified) (?:compromise|malware infection)', '', narrative, flags=re.I)
                if re.search(pattern,cleaned,re.I): raise ValueError(reason)

        # Preserve NVIDIA analysis, mapping, and actions after structural/evidence checks.
        # This is not a semantic proof of every model sentence; human review remains mandatory.
        candidate = redact(candidate)
        candidate['analysis_reasoning'] += ' Human review required: model interpretations are advisory; validate all claims against supplied telemetry.'
        return candidate
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        return failure('verification_failed', str(exc))


from lfx.custom.custom_component.component import Component
from lfx.io import MessageTextInput, Output
from lfx.schema.message import Message

class SOCInputValidation(Component):
    display_name = 'SOC Input Validation'
    description = 'Strict JSON and complete playbook scoring. Invalid alerts return JSON and bypass NVIDIA analysis.'
    icon = 'shield-check'
    name = 'SOCInputValidation'
    inputs = [MessageTextInput(name='alert', display_name='Alert JSON', required=True)]
    outputs = [Output(display_name='Validated Alert', name='validated', method='validate_alert')]

    def validate_alert(self) -> Message:
        payload = prepare(self.alert)
        self.status = payload.get('report', payload.get('deterministic_report'))
        return Message(text=json.dumps(payload, allow_nan=False))
