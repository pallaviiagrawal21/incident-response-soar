# MITRE ATT&CK Mapping

Consolidated view of every MITRE ATT&CK Enterprise technique referenced across both playbooks. Each playbook's own Markdown document has the same table in context (Section 11 of each) alongside the automation cross-reference showing which steps address which technique.

## Phishing → Credential Harvesting → Lateral Movement

Source: [`config/playbooks/phishing_lateral_movement.yaml`](../config/playbooks/phishing_lateral_movement.yaml) · [`playbooks/phishing_lateral_movement.md`](../playbooks/phishing_lateral_movement.md)

| Tactic | Technique | Technique Name |
|---|---|---|
| Initial Access | T1566.002 | Phishing: Spearphishing Link |
| Credential Access | T1078 | Valid Accounts |
| Discovery | T1087 | Account Discovery |
| Lateral Movement | T1021 | Remote Services |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols |

## Ransomware (Initial Access → Encryption → Lateral Movement)

Source: [`config/playbooks/ransomware.yaml`](../config/playbooks/ransomware.yaml) · [`playbooks/ransomware.md`](../playbooks/ransomware.md)

| Tactic | Technique | Technique Name |
|---|---|---|
| Initial Access | T1190 | Exploit Public-Facing Application |
| Execution | T1059 | Command and Scripting Interpreter |
| Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools |
| Discovery | T1135 | Network Share Discovery |
| Lateral Movement | T1021.001 | Remote Services: Remote Desktop Protocol |
| Impact | T1486 | Data Encrypted for Impact |

## Tactic coverage across both playbooks

| Tactic | Phishing playbook | Ransomware playbook |
|---|---|---|
| Initial Access | ✅ T1566.002 | ✅ T1190 |
| Execution | | ✅ T1059 |
| Credential Access | ✅ T1078 | |
| Discovery | ✅ T1087 | ✅ T1135 |
| Defense Evasion | | ✅ T1562.001 |
| Lateral Movement | ✅ T1021 | ✅ T1021.001 |
| Command and Control | ✅ T1071.001 | |
| Impact | | ✅ T1486 |

## Schema enforcement

`MitreMapping` (in `src/ir_soar/models/playbook.py`) validates every technique ID against the pattern `T####` or `T####.###` and restricts `tactic` to the closed set of standard MITRE Enterprise tactic names — a typo'd tactic name or malformed technique ID fails playbook validation (`ir-soar validate-playbook <id>`) rather than silently producing an incorrect mapping.

## Adding mappings to a new playbook

```yaml
mitre_attack:
  - tactic: "Collection"          # must be one of the 14 standard MITRE Enterprise tactics
    technique: "T1213"             # T#### or T####.### — validated by regex
    technique_name: "Data from Information Repositories"   # optional, human-readable
```

See [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/) for the authoritative technique list.
