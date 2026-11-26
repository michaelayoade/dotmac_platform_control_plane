import hashlib,json,os,socket,stat,subprocess
from pathlib import Path
if os.geteuid()!=0 or socket.gethostname()!='dotmac-s3':raise SystemExit('REFUSED host')
root=Path('/root/cp-reader-host-gated-20261125')
PINS={'host_gate.py': '6a7f5175f7e3ec5c2f4dbcf4acde036a3f308c75772d82242cafad4305f98a5a', 'orchestrator.py': 'a8f67bd4a32ba65abc7bb68e7c6129b18b7135c71bd8b73fb5a28a8446a4309e', 'revocation_sql.py': '0e6733f2032173338b611b087530790d144a3403bcdff2418c21836e637b969a', 'bootstrap_api.py': '377f7379c2aa838197bce511736e6af5a2854a25b5b3d0d53dfd9e7de710e172', 'audit.py': '86e9858f0e1a1ee5d19456a2dba730721e8da982c09aa248446fb81d1bbc28c9', 'runtime.py': 'ca43326f10176e640a0031367db2ec28a3dbdd62326875789c35e4cd3cd8d45a', 'canary.config.json': 'bcb014e7b58d134d0277302fcf76308cfadf46eb2704c66d0377f11cb5ccf1d3', 'bootstrap.config.json': 'd18d24f5fb3f5a36336a18e7b58e6eeceb7cbff2399910f8f6097b3e5822ad21'}
for name,pin in PINS.items():
 path=root/name;st=path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077 or st.st_nlink!=1:raise SystemExit('REFUSED source protection')
 if hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise SystemExit('REFUSED source binding')

def summarize_receipt(data, packet):
    """Closed successful-bootstrap contract; never return arbitrary receipt fields."""
    keys = {"schema", "run", "phase", "source_pins", "container_pins", "started_at", "status", "events", "failure"}
    if (type(data) is not dict or set(data) != keys or data["schema"] != "cp_host_gated_receipt.v1"
            or data["status"] != "BOOTSTRAP_PASSED" or data["failure"] is not None
            or data["run"] != packet["expected_run"] or data["run"] != "cp-host-20261125-r1" or data["phase"] != "bootstrap"
            or data["source_pins"] != packet["source_pins"] or data["container_pins"] != packet["container_pins"]
            or type(data["started_at"]) is not str or len(data["started_at"]) > 64):
        return None
    stages = ["exclusive_attempt_recorded", "pinned_runtime_ready", "before_create_cp_reader", "cp_reader_created",
              "before_mint_bootstrap", "bootstrap_token_bound", "bootstrap_same_token_200", "before_create_exact_cp_team",
              "cp_team_created", "before_add_exact_cp_member", "cp_metadata_ready", "before_exact_revocation",
              "revocation_committed_absence", "same_token_401", "finished"]
    events = data["events"]
    if type(events) is not list or len(events) != len(stages) or any(type(e) is not dict or e.get("stage") != s for e, s in zip(events, stages)):
        return None
    uid = events[3].get("user_id")
    team_id = events[8].get("team_id")
    binding = events[5].get("binding")
    if (type(uid) is not int or uid <= 5 or uid == 9 or type(team_id) is not int or team_id <= 4
            or type(binding) is not dict):
        return None
    if set(binding) != {"kind", "token_id", "user_id", "username", "token_name", "scope", "created_unix"}:
        return None
    if (binding["kind"] != "bootstrap" or type(binding["token_id"]) is not int or binding["token_id"] <= 0
            or binding["token_id"] in (2, 16, 26, 28, 29) or type(binding["user_id"]) is not int or binding["user_id"] != 1
            or binding["username"] != "dotmac-admin" or binding["token_name"] != packet["bootstrap_token_name"]
            or binding["scope"] != "write:organization" or type(binding["created_unix"]) is not int or binding["created_unix"] <= 0):
        return None
    for index, event in enumerate(events):
        expected = {"stage": stages[index]}
        if index == 2:
            expected["username"] = "cp-bundle-reader"
        elif index == 3:
            expected["user_id"] = uid
        elif index == 4:
            expected.update(token_name=packet["bootstrap_token_name"], scope="write:organization")
        elif index in (5, 11, 12, 13):
            event_binding = event.get("binding")
            if (type(event_binding) is not dict or set(event_binding) != set(binding)
                    or any(type(event_binding[key]) is not type(value) or event_binding[key] != value
                           for key, value in binding.items())):
                return None
            expected["binding"] = binding
        elif index in (8, 9):
            expected["team_id"] = team_id
        if event != expected:
            return None
    return {"schema": "cp_bootstrap_public_summary.v1", "status": "BOOTSTRAP_PASSED", "run": packet["expected_run"],
            "phase": "bootstrap", "source_pins": packet["source_pins"], "container_pins": packet["container_pins"],
            "user_id": uid, "team_id": team_id, "token_id": binding["token_id"], "token_name": packet["bootstrap_token_name"],
            "scope": "write:organization", "proof_stages": stages}
CONTEXT={'expected_run': 'cp-host-20261125-r1', 'source_pins': {'host_gate.py': '6a7f5175f7e3ec5c2f4dbcf4acde036a3f308c75772d82242cafad4305f98a5a', 'orchestrator.py': 'a8f67bd4a32ba65abc7bb68e7c6129b18b7135c71bd8b73fb5a28a8446a4309e', 'revocation_sql.py': '0e6733f2032173338b611b087530790d144a3403bcdff2418c21836e637b969a', 'bootstrap_api.py': '377f7379c2aa838197bce511736e6af5a2854a25b5b3d0d53dfd9e7de710e172', 'audit.py': '86e9858f0e1a1ee5d19456a2dba730721e8da982c09aa248446fb81d1bbc28c9', 'runtime.py': 'ca43326f10176e640a0031367db2ec28a3dbdd62326875789c35e4cd3cd8d45a'}, 'container_pins': {'forgejo_container_id': '4482c4d5bb7413d5efafdfa2e9cef7253eb1a1293efa8109a7e2d478eae64ad1', 'forgejo_image_id': 'sha256:946243edbab116d5bb78b73ea68af6f3d69229ba1b1ed958dd82c3481167f3e0', 'database_container_id': '40d899c6fbbf30e7c522990af1c6a22bba8e908c461e32023f1687e96eac2bcb', 'database_image_id': 'sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'}, 'bootstrap_token_name': 'cp-org-bootstrap-20261125-r1'}

result={'status':'UNKNOWN_HELPER_OUTCOME_NO_RETRY','run':'cp-host-20261125-r1'}
try:
 child=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(root/'host_gate.py'),'--config',str(root/'bootstrap.config.json'),'--phase','bootstrap','--apply','--expect-config-sha256','d18d24f5fb3f5a36336a18e7b58e6eeceb7cbff2399910f8f6097b3e5822ad21','--accepted-canary-receipt','/root/cp-reader-host-gated-receipts/cp-host-20261125-r1/canary/receipt.json'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=360,env={'PATH':'/usr/bin:/bin'})
 result['helper_exit_code']=child.returncode;result['stderr_sha256']=hashlib.sha256(child.stderr).hexdigest()
 receipt=Path('/root/cp-reader-host-gated-receipts/cp-host-20261125-r1/bootstrap/receipt.json');st=receipt.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077 or st.st_nlink!=1 or st.st_size>1048576:raise ValueError('receipt protection')
 raw=receipt.read_bytes();data=json.loads(raw);result['receipt_sha256']=hashlib.sha256(raw).hexdigest()
 summary=summarize_receipt(data,CONTEXT)
 result['status']='STOPPED_NATIVE_BOOTSTRAP_NO_RETRY'
 if child.returncode==0 and summary is not None:
  source=(root/'host_gate.py').read_bytes()
  if hashlib.sha256(source).hexdigest()!=CONTEXT['source_pins']['host_gate.py']:raise ValueError('postcheck source drift')
  owner={'__name__':'reviewed_host_owner','__file__':str(root/'host_gate.py')}
  exec(compile(source,str(root/'host_gate.py'),'exec'),owner)
  cfg_raw=(root/'bootstrap.config.json').read_bytes()
  if hashlib.sha256(cfg_raw).hexdigest()!='d18d24f5fb3f5a36336a18e7b58e6eeceb7cbff2399910f8f6097b3e5822ad21':raise ValueError('postcheck config drift')
  cfg=json.loads(cfg_raw)
  modules={n:owner['load_module'](n,CONTEXT['source_pins'][n]) for n in ['runtime.py','audit.py','bootstrap_api.py','revocation_sql.py']}
  backend=owner['Backend'](cfg,modules['runtime.py'],modules['audit.py'],modules['bootstrap_api.py'],modules['revocation_sql.py'])
  backend.check_container('forgejo')
  metadata=backend.metadata('cp-bundle-reader')
  backend.require_cp_ready(metadata,summary['team_id'],summary['user_id'])
  result['post_cleanup_cp_audit']=True;result['receipt_summary']=summary;result['status']='BOOTSTRAP_PASSED'
except Exception:pass
print(json.dumps(result,sort_keys=True))
