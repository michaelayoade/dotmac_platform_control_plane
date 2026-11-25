import hashlib,json,os,socket,stat,subprocess
from pathlib import Path
if os.geteuid()!=0 or socket.gethostname()!='dotmac-s3':raise SystemExit('REFUSED host')
root=Path('/root/cp-reader-host-gated-20261125')
PINS={'host_gate.py': '6a7f5175f7e3ec5c2f4dbcf4acde036a3f308c75772d82242cafad4305f98a5a', 'orchestrator.py': 'a8f67bd4a32ba65abc7bb68e7c6129b18b7135c71bd8b73fb5a28a8446a4309e', 'revocation_sql.py': '0e6733f2032173338b611b087530790d144a3403bcdff2418c21836e637b969a', 'bootstrap_api.py': '377f7379c2aa838197bce511736e6af5a2854a25b5b3d0d53dfd9e7de710e172', 'audit.py': '86e9858f0e1a1ee5d19456a2dba730721e8da982c09aa248446fb81d1bbc28c9', 'runtime.py': 'ca43326f10176e640a0031367db2ec28a3dbdd62326875789c35e4cd3cd8d45a', 'canary.config.json': 'bcb014e7b58d134d0277302fcf76308cfadf46eb2704c66d0377f11cb5ccf1d3'}
for name,pin in PINS.items():
 path=root/name
 st=path.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077 or st.st_nlink!=1:raise SystemExit('REFUSED source protection')
 if hashlib.sha256(path.read_bytes()).hexdigest()!=pin:raise SystemExit('REFUSED source binding')

def summarize_receipt(data, packet):
    """Closed successful-canary contract; never return arbitrary receipt fields."""
    keys = {"schema", "run", "phase", "source_pins", "container_pins", "started_at", "status", "events", "failure"}
    if (type(data) is not dict or set(data) != keys or data["schema"] != "cp_host_gated_receipt.v1"
            or data["status"] != "CANARY_PASSED" or data["failure"] is not None
            or data["run"] != packet["expected_run"] or data["phase"] != "canary"
            or data["source_pins"] != packet["source_pins"] or data["container_pins"] != packet["container_pins"]
            or type(data["started_at"]) is not str or len(data["started_at"]) > 64):
        return None
    stages = ["exclusive_attempt_recorded", "pinned_runtime_ready", "before_create_canary", "canary_created",
              "before_mint_canary", "canary_token_bound", "canary_same_token_200", "before_exact_revocation",
              "revocation_committed_absence", "same_token_401", "finished"]
    events = data["events"]
    if type(events) is not list or len(events) != len(stages) or any(type(e) is not dict or e.get("stage") != s for e, s in zip(events, stages)):
        return None
    uid = events[3].get("user_id")
    binding = events[5].get("binding")
    if type(uid) is not int or uid <= 5 or type(binding) is not dict:
        return None
    if set(binding) != {"kind", "token_id", "user_id", "username", "token_name", "scope", "created_unix"}:
        return None
    if (binding["kind"] != "canary" or type(binding["token_id"]) is not int or binding["token_id"] <= 0
            or binding["token_id"] in (2, 16, 26, 28) or type(binding["user_id"]) is not int or binding["user_id"] != uid
            or binding["username"] != packet["canary_username"] or binding["token_name"] != packet["canary_token_name"]
            or binding["scope"] != "read:user" or type(binding["created_unix"]) is not int or binding["created_unix"] <= 0):
        return None
    for index, event in enumerate(events):
        expected = {"stage": stages[index]}
        if index == 2:
            expected["username"] = packet["canary_username"]
        elif index == 3:
            expected["user_id"] = uid
        elif index == 4:
            expected.update(token_name=packet["canary_token_name"], scope="read:user")
        elif index in (5, 7, 8, 9):
            expected["binding"] = binding
        if event != expected:
            return None
    return {"schema": "cp_canary_public_summary.v1", "status": "CANARY_PASSED", "run": packet["expected_run"],
            "phase": "canary", "source_pins": packet["source_pins"], "container_pins": packet["container_pins"],
            "user_id": uid, "token_id": binding["token_id"], "token_name": packet["canary_token_name"],
            "scope": "read:user", "proof_stages": stages}
CONTEXT={'expected_run': 'cp-host-20261125-r1', 'source_pins': {'host_gate.py': '6a7f5175f7e3ec5c2f4dbcf4acde036a3f308c75772d82242cafad4305f98a5a', 'orchestrator.py': 'a8f67bd4a32ba65abc7bb68e7c6129b18b7135c71bd8b73fb5a28a8446a4309e', 'revocation_sql.py': '0e6733f2032173338b611b087530790d144a3403bcdff2418c21836e637b969a', 'bootstrap_api.py': '377f7379c2aa838197bce511736e6af5a2854a25b5b3d0d53dfd9e7de710e172', 'audit.py': '86e9858f0e1a1ee5d19456a2dba730721e8da982c09aa248446fb81d1bbc28c9', 'runtime.py': 'ca43326f10176e640a0031367db2ec28a3dbdd62326875789c35e4cd3cd8d45a'}, 'container_pins': {'forgejo_container_id': '4482c4d5bb7413d5efafdfa2e9cef7253eb1a1293efa8109a7e2d478eae64ad1', 'forgejo_image_id': 'sha256:946243edbab116d5bb78b73ea68af6f3d69229ba1b1ed958dd82c3481167f3e0', 'database_container_id': '40d899c6fbbf30e7c522990af1c6a22bba8e908c461e32023f1687e96eac2bcb', 'database_image_id': 'sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777'}, 'canary_username': 'cp-revoke-proof-20261125-r1', 'canary_token_name': 'cp-canary-read-20261125-r1'}

result={'status':'UNKNOWN_HELPER_OUTCOME_NO_RETRY','run':'cp-host-20261125-r1'}
try:
 child=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(root/'host_gate.py'),'--config',str(root/'canary.config.json'),'--phase','canary','--apply','--expect-config-sha256','bcb014e7b58d134d0277302fcf76308cfadf46eb2704c66d0377f11cb5ccf1d3'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=240,env={'PATH':'/usr/bin:/bin'})
 result['helper_exit_code']=child.returncode
 result['stderr_sha256']=hashlib.sha256(child.stderr).hexdigest()
 receipt=Path('/root/cp-reader-host-gated-receipts/cp-host-20261125-r1/canary/receipt.json')
 st=receipt.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077 or st.st_nlink!=1 or st.st_size>1048576:raise ValueError('receipt protection')
 raw=receipt.read_bytes();data=json.loads(raw)
 result['receipt_sha256']=hashlib.sha256(raw).hexdigest()
 summary=summarize_receipt(data,CONTEXT)
 if child.returncode==0 and summary is not None:
  result['receipt_summary']=summary
  result['status']='CANARY_PASSED'
 else:result['status']='STOPPED_NATIVE_CANARY_NO_RETRY'
except Exception:pass
print(json.dumps(result,sort_keys=True))
