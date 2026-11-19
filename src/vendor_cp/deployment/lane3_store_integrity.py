"""Read-only integrity check of the Lane 3 store's code and triggers (CP-5, E10a).

The store's safety lives in its function bodies and in six tables' triggers: a
`SECURITY DEFINER` function whose body was edited, or an append-only trigger that
was disabled, defeats every guarantee while every privilege check still passes.
So this pins, from the migration as written:

* the sha256 of `pg_get_functiondef` for EVERY function in `cp_lane3` (the
  definition covers the argument list, language, `SECURITY DEFINER`, the pinned
  `search_path`, volatility and the body), including `store_now()`, which must be
  exactly `clock_timestamp()`;
* every non-internal trigger: its table, its enable state (`O`, enabled), and the
  sha256 of `pg_get_triggerdef`.

Beyond the code and triggers it also checks, so a POST-migration change is caught:

* the sha256 of `public.forbid_mutation_of_append_only_table()` (the owner of
  `public` could replace it and defeat all six append-only tables);
* the privilege read-back of `v023_lane3_store` (`SCHEMA_ACL_SQL` ...
  `DEFAULT_ACL_SQL`, read FROM that migration so there is one source): no ACL entry
  but the owner's, and no default-privilege rule;
* ONE owner for the schema and every object in it;
* the sha256 of `pg_get_constraintdef` and `pg_get_indexdef` for every constraint
  and index (the `-spent` UNIQUE, the one-release PK, the fingerprint-derivation
  CHECK, `run_bindings_role_name_key` ...);
* no `pg_rewrite` rule and no row-level-security policy on a `cp_lane3` table;
* PostgreSQL major version 16: the digests are of PG16's catalogue output, so any
  other major is `repin-required:...` (exit 3), never a misleading digest mismatch.

The set must match exactly: a function or trigger that is extra, missing, changed
or not enabled is a violation. CI runs it on the migrated schema, and the E10a
read-back runs it on production:

    LANE3_STORE_CHECK_DATABASE_URL=... \\
        python -m vendor_cp.deployment.lane3_store_integrity

Exit 0 only when there is no violation; 2 on any violation; it prints names only.
Re-pin by running the migration on a scratch database and reading the catalogue:
a change to a pinned digest is a reviewed diff, never an incidental one.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from sqlalchemy import text

__all__ = [
    "ADMIN_DSN_ENV",
    "FUNCTION_DEFINITION_SHA256",
    "TRIGGERS",
    "PUBLIC_FUNCTIONS",
    "CONSTRAINTS",
    "INDEXES",
    "PINNED_MAJOR",
    "check_store_integrity",
    "main",
]

ADMIN_DSN_ENV: Final = "LANE3_STORE_CHECK_DATABASE_URL"

# BEGIN PINS (generated from v023_lane3_store; see the module docstring)
FUNCTION_DEFINITION_SHA256: Final[Mapping[str, str]] = {
    "acquire(text, text, text, text, integer, jsonb, text, jsonb)": (
        "757adc53fd1b8bce11344bf3785ec088ca135923bcefa4d229f6fadee5a14897"
    ),
    "bind_document(uuid, bytea, text)": (
        "2065883d75011a25eb3f3d52ccd833019904fefd8998daac0c3c0d2a8d7c8ec0"
    ),
    "covers(uuid, text)": (
        "3fed9fe44a9e213daae67f0386fb43f76d225de5cd8cac6ef58c9ee2db228816"
    ),
    "database_time()": (
        "b8d0ac406814b6fb6abcb00735df53053410039427b58762888d0a339b57e890"
    ),
    "e10_receipt(text, text, text)": (
        "5cf773980593744b129aaf12342b2fd3cb4ee5562cc82ff5c9d8caab00f6c48b"
    ),
    "forbid_current_lease_removal()": (
        "73eccfc8e980c2c637797a3e9f0c2c7a75373210eae64ee7b3deff11d63ce86c"
    ),
    "guard_current_lease_update()": (
        "c8a53ab366b5558c1d370d91d45479eea8008bde9628b10a50da5856469db18a"
    ),
    "guard_lease_update()": (
        "21e76d5bab6d702c5ff23cb5703f7b9e0d4a257f4d035f1ac7388c00e8cc6eda"
    ),
    "release(uuid, bytea, text, text, text, text, timestamp with time zone, boolean)": (
        "f0ddab36995fe7cd328a150ce853cb4160604e663c5c8039cc373a8b76a25f84"
    ),
    "released_at(text)": (
        "ac1f2cfe4452ee9a91290ee0780711b6bddbc513c61570f8cde00ccb883faa35"
    ),
    "require_any_binding()": (
        "4f051b19227aef1c8dea51411271525820aa69809b547400beda4e5f47374539"
    ),
    "require_binding(text, text)": (
        "316870b91a38545d045ccff119042c3514eb5e0116b1817371689b716ec34587"
    ),
    "require_host_binding(text)": (
        "cd93c872e1796edc02c92609c6ebb4b6b68ebae148d23fc73b6f6cc31cd076c2"
    ),
    "stamp_binding_time()": (
        "588b6e5c6d521660fa8cb30359d2a46464af9820f9ec73f5a186babffd948da5"
    ),
    "stamp_destruction_time()": (
        "23d2bf6962ff96dee14360819b7bb59538acaff0efc43fddac8f2b95fb91e6b8"
    ),
    "stamp_receipt_time()": (
        "f357638e31a1601389dae18c1853e985778a5e539e28aed49fe4583cf828ba55"
    ),
    "stamp_release_time()": (
        "83a1450d104a389e72ad57d815b6bca7bc7278795c9f50ab8c5bf0cdfe9a5af0"
    ),
    "standing(text)": (
        "ea6bbe5145d12fb4aa78dc41fad93696934b189b25a483ea5d6c4f0b7e0fe302"
    ),
    "store_now()": ("a24607462886a8a2aece5779354304e2f786ae706db0e9c8d1831eb4b82f9cc6"),
}

#: `trigger name -> (table, enable state, sha256 of pg_get_triggerdef)`.
TRIGGERS: Final[Mapping[str, tuple[str, str, str]]] = {
    "trg_e10_destructions_append_only": (
        "e10_destructions",
        "O",
        "417536e63a7c8f5905950c3d1f8dd9835fda8006c648474ea35e592542c5d43e",
    ),
    "trg_e10_destructions_append_only_truncate": (
        "e10_destructions",
        "O",
        "03613ac0b6292b16f7c26ef893c5d725ecdbb3919f0ffb59e3909cec55e0ec7c",
    ),
    "trg_e10_destructions_stamp": (
        "e10_destructions",
        "O",
        "eca80d78f3da763f5615b2f2add571e018f1d22e518e6ea830c500791810d0b5",
    ),
    "trg_e10_receipts_append_only": (
        "e10_receipts",
        "O",
        "3935cec713d58b8852823a054046f69397fb92d6573eb0dc43ce49f5f3fb68b7",
    ),
    "trg_e10_receipts_append_only_truncate": (
        "e10_receipts",
        "O",
        "e13c557e942b3e247b2dabe9d8b5916cb4fd3c2d0b43f9ff0b499988f15ed7a5",
    ),
    "trg_e10_receipts_stamp": (
        "e10_receipts",
        "O",
        "f9dfa8b72ccf4c0c47fcb4e6c1539338e7beefd0cce13caddc3ef6041464f4ea",
    ),
    "trg_host_current_lease_delete": (
        "host_current_lease",
        "O",
        "042125c16bfe0e10ef4f3787c3bafac28db24ac5d04ed0bc7b0d4f6c3e0eab44",
    ),
    "trg_host_current_lease_truncate": (
        "host_current_lease",
        "O",
        "bebc9bc0cd6be74e1888433b3e08b9b994369521e198785b3a3924d14255f067",
    ),
    "trg_host_current_lease_update": (
        "host_current_lease",
        "O",
        "40118efd6b7ef1852dff944f0d43a2954b6a60248b74406cc5bf803a44b9d466",
    ),
    "trg_host_lease_releases_append_only": (
        "host_lease_releases",
        "O",
        "a07205bf1aecde719dd3fca842e014167f51a703047dc91e35afca7ea62d304e",
    ),
    "trg_host_lease_releases_append_only_truncate": (
        "host_lease_releases",
        "O",
        "cdfdeec99f5affe8dcb41beaaa8f96e2d3bbc850ee7e91caa8377c7985b59289",
    ),
    "trg_host_lease_releases_stamp": (
        "host_lease_releases",
        "O",
        "021d7d797bf4e03e77d669e7e542fb8498f36c0879afc5e9f25a5427a05c5624",
    ),
    "trg_host_leases_delete": (
        "host_leases",
        "O",
        "c113b7967d262e01dcd6ab4c9d45301e440d5e47f3634d1eb1ba5e147fdd2da5",
    ),
    "trg_host_leases_truncate": (
        "host_leases",
        "O",
        "47e7e2bf909d080fc1d2a737e59fa4fa48a9429bd7512cc21a235e43f6e684b6",
    ),
    "trg_host_leases_update": (
        "host_leases",
        "O",
        "3d221c48658071db26d86b0043df23defe9c0ad98c03a73db5c6c7b4a285d06c",
    ),
    "trg_run_bindings_append_only": (
        "run_bindings",
        "O",
        "7d1a24660b8501affc414ce94908bee81df0ff45da498d4176d17d1aa0741ba2",
    ),
    "trg_run_bindings_append_only_truncate": (
        "run_bindings",
        "O",
        "fcca070a1c71bfaf8b8d704f79b97b00e0dacb733a1c69d377c67b335ea032c1",
    ),
    "trg_run_bindings_stamp": (
        "run_bindings",
        "O",
        "443acd3c64ba55898921dce4266c179b657b49c89732ea8f464cdba63df56589",
    ),
}

PUBLIC_FUNCTIONS: Final[Mapping[str, str]] = {
    "public.forbid_mutation_of_append_only_table()": (
        "a84c545276143a3dc138a57375459fb42daf23924c7030a0a9cdd1e42e87a74f"
    ),
}
CONSTRAINTS: Final[Mapping[str, str]] = {
    "e10_destructions.e10_destructions_check": (
        "3951bb4ef986953d6bc56d2479e55cd9ba07243b09c7f179a2699c0b88072e7f"
    ),
    "e10_destructions.e10_destructions_evidence_digest_check": (
        "6cc458fa74e2fe5d952a8ce1cdbbb8d576a0ef6aca47376c8e004e8587dafdf2"
    ),
    "e10_destructions.e10_destructions_installed_attestation_digest_check": (
        "f4b6dae024c27dd5ae012c3af3b0a3cb8fecbd2855f3ac276ba831da93bf41b3"
    ),
    "e10_destructions.e10_destructions_pkey": (
        "f732a7980b71e86168c87444f460896113f0fd890f08fe7d4b8f2d963ea10ccd"
    ),
    "e10_destructions.e10_destructions_receipt_ref_fkey": (
        "5969e26b0035b41692a4ed130ebf64abd0e7e8325abe6434f71cb62724073741"
    ),
    "e10_destructions.e10_destructions_recorded_by_check": (
        "1f3ad34bb9488f398da9451ab04c9f39fd990ec8329e01cb45687ae36fb943e8"
    ),
    "e10_destructions.e10_destructions_route_check": (
        "2cde6b09d6bd4a0dc19d5976323b5efa4c8b903c2c1ec5bcf1a56dd83bf4927e"
    ),
    "e10_receipts.e10_receipts_check": (
        "01ed7c9ed5d3d0e25dc1b51b09f606e92a429cbf0adcbd673fd0e6335d1daeaf"
    ),
    "e10_receipts.e10_receipts_enrolment_uuid_key": (
        "e3cd9507fd10ce1a2c1e86d2e7cf31a6fc81e17732a81e5b3140023c0c231bbf"
    ),
    "e10_receipts.e10_receipts_host_id_check": (
        "393bc83d2ca9c1fe3f1f419976822dc7bd8cd3ffe023df6eb732c78212aa19b6"
    ),
    "e10_receipts.e10_receipts_incarnation_public_key_b64url_check": (
        "1fd75c137b30b83c7b5b430e1cf68cc06d3fbb118453a4681ffc1122db15a0d3"
    ),
    "e10_receipts.e10_receipts_key_custody_pointer_check": (
        "f0ec9d37be5b86a1fbf4891c6012ef265c9c17ac47fbab4faae50bc02502d0c9"
    ),
    "e10_receipts.e10_receipts_machine_id_check": (
        "893fc8398953de02713893cd02db679d38a7d9bc892cea1e4331b2d1ccc1869e"
    ),
    "e10_receipts.e10_receipts_pkey": (
        "f732a7980b71e86168c87444f460896113f0fd890f08fe7d4b8f2d963ea10ccd"
    ),
    "e10_receipts.e10_receipts_receipt_ref_check": (
        "01a183276d7a969fe1d595dcefe4f44f29e17066cf50ec0f02e8a6a387c75132"
    ),
    "e10_receipts.e10_receipts_recorded_by_check": (
        "1f3ad34bb9488f398da9451ab04c9f39fd990ec8329e01cb45687ae36fb943e8"
    ),
    "e10_receipts.e10_receipts_ssh_host_key_fingerprint_check": (
        "cb4cbbc14cad7dd8e637a9f320f8ff89eb3a1766e96aeee951ed781278e25b8f"
    ),
    "e10_receipts.e10_receipts_vm_alias_check": (
        "eab1e716c6dc5038812a51c75deb3e8413cf047596eb69faefaa0b51d5d80cef"
    ),
    "e10_receipts.e10_receipts_vm_slot_check": (
        "1dea2ff2819945991ecb37504c1f103eb2b6683d59ba22b148dff92c207af1f8"
    ),
    "host_current_lease.host_current_lease_host_id_check": (
        "393bc83d2ca9c1fe3f1f419976822dc7bd8cd3ffe023df6eb732c78212aa19b6"
    ),
    "host_current_lease.host_current_lease_pkey": (
        "d127547073eea25f2a92c5579e3babd52c4eca5165cf02134459518afb670167"
    ),
    "host_lease_releases.host_lease_releases_lease_id_fkey": (
        "90a3f45ffa425f77822b8a070c8b2831b53c04231555d5e3647fa4e033cab164"
    ),
    "host_lease_releases.host_lease_releases_pkey": (
        "c941384e76f8623246319cbda5ad4dc19024aa7fd10bf12a1eb103fb707dc136"
    ),
    "host_lease_releases.host_lease_releases_release_digest_check": (
        "f6d8aaa2dc751bb31b6c8855027e7c064520430c611edc39c1722c9131941adf"
    ),
    "host_leases.host_leases_authorization_run_check": (
        "be8a8276ff57f53cc9463241241ee4cb0fcbde632cf1a6010198bfe08085757b"
    ),
    "host_leases.host_leases_check": (
        "b0b3de0101d50ba62f00985237114b5ac439149fa2fcec8d963899102f0fb43e"
    ),
    "host_leases.host_leases_check1": (
        "67d67e8b5b89b0270125e3d87089de5f4de0634568832f77a595e651c9364e5b"
    ),
    "host_leases.host_leases_controller_identity_check": (
        "0f1440eb203399578a1a947fc38c05176a5499cd713a4d7c5b346a85611fa5c7"
    ),
    "host_leases.host_leases_e10_receipt_ref_fkey": (
        "71240663960418f57fbd9776ab0bf16a56e5228564e159c14624b82bf88ff4d8"
    ),
    "host_leases.host_leases_host_id_fkey": (
        "9e8cc12f4b820685efa0f7a039103a73e23884710a5b77a55f2be5e0f960baa0"
    ),
    "host_leases.host_leases_lease_digest_check": (
        "c2805eff5773d421163b2a50cff091b4c728bf4e8dc2af8355e333ae34eff8e4"
    ),
    "host_leases.host_leases_pkey": (
        "c941384e76f8623246319cbda5ad4dc19024aa7fd10bf12a1eb103fb707dc136"
    ),
    "host_leases.host_leases_reprovision_receipt_ref_fkey": (
        "5f98c613a26420beaac6b0f17b3b84fc30fbd356f867a167b7f4e4d5194bc6a0"
    ),
    "host_leases.host_leases_reprovision_receipt_ref_key": (
        "505aeade0dbbb221e0b326a201c1a7480d69372b545968729c9490c241681764"
    ),
    "host_leases.host_leases_ttl_seconds_check": (
        "d6293d75b03ab70b4e055ca5044f5ada82cc9c3a1b43087d715edae7ea8feb8b"
    ),
    "host_leases.host_leases_workload_principal_check": (
        "0e51ed45d4d425e25ddc7b6a49017c421ee9a550125c4d24dfae2b11b6be1c09"
    ),
    "run_bindings.run_bindings_authorization_run_check": (
        "be8a8276ff57f53cc9463241241ee4cb0fcbde632cf1a6010198bfe08085757b"
    ),
    "run_bindings.run_bindings_check": (
        "b657c328242d639472d3613b8cc36192b9bd711459cf3c0eeafd9460438b8ece"
    ),
    "run_bindings.run_bindings_host_id_check": (
        "393bc83d2ca9c1fe3f1f419976822dc7bd8cd3ffe023df6eb732c78212aa19b6"
    ),
    "run_bindings.run_bindings_pkey": (
        "a02719c37ffcb7e433c9e461282ba4379f4a750ed88de1852e505795d64729d3"
    ),
    "run_bindings.run_bindings_recorded_by_check": (
        "1f3ad34bb9488f398da9451ab04c9f39fd990ec8329e01cb45687ae36fb943e8"
    ),
    "run_bindings.run_bindings_role_name_check": (
        "fc56df0f8e73d4779829fcd2989568ece38049760c0813636ada36f157a6e0cd"
    ),
    "run_bindings.run_bindings_role_name_key": (
        "712999f3dd07285052b5c57690b72b954b9d20f966741b24a317b501412f1d34"
    ),
}
INDEXES: Final[Mapping[str, str]] = {
    "e10_destructions_pkey": (
        "95f5a3b63ca62e4751d3d7eb637474f8ad1dfa63b7d4e318e4880d5846d02fd6"
    ),
    "e10_receipts_enrolment_uuid_key": (
        "b7b12fe0fbfdf32ba4aa9554007995e13bb5da29e3d542e52d03a9ee076058b1"
    ),
    "e10_receipts_pkey": (
        "177072d6e701ca6199fe8f02b6a6da195f0f995203626b8b03c4c01a0be26c22"
    ),
    "host_current_lease_pkey": (
        "066fc733181e1f376924679f16f73dc7c9c8d14fff536389ed853fa06d6556a5"
    ),
    "host_lease_releases_pkey": (
        "d748aabe5251b80d9fae4ed7f994743f2ec78b5a09ba1635ea793b2837f41ddb"
    ),
    "host_leases_pkey": (
        "06c7fb34cc09468287266ce9ea4e08f3e7d5f3280e13f5325925a840e9fb03b0"
    ),
    "host_leases_reprovision_receipt_ref_key": (
        "e99cc9abca6146c8a03eec4ee24407407a6bfcfddcd4d846dbf69032cde5db66"
    ),
    "run_bindings_pkey": (
        "286fec0b1139abb7315f38f750f93648857ec490dab1049f1db0d8860a5272cc"
    ),
    "run_bindings_role_name_key": (
        "153243c2ea008ecf36fb477d48ddcb21f74b96a90a05eb64154e477e60d670ac"
    ),
}
# END PINS

_PUBLIC_NAMES: Final = ["forbid_mutation_of_append_only_table"]

PINNED_MAJOR: Final = 16
ACL_QUERY_NAMES: Final = (
    "SCHEMA_ACL_SQL",
    "RELATION_ACL_SQL",
    "COLUMN_ACL_SQL",
    "FUNCTION_ACL_SQL",
    "DEFAULT_ACL_SQL",
)
_MIGRATION_FILE: Final = "v023_lane3_store.py"

_VERSION_SQL: Final = "SHOW server_version_num"
_FUNCTIONS_SQL: Final = (
    "SELECT p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')', "
    "pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
    "WHERE n.nspname = 'cp_lane3'"
)
_PUBLIC_FUNCTIONS_SQL: Final = (
    "SELECT n.nspname || '.' || p.proname || '(' || "
    "pg_catalog.oidvectortypes(p.proargtypes) || ')', "
    "pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
    "WHERE n.nspname = 'public' AND p.proname = ANY(:names)"
)
_TRIGGERS_SQL: Final = (
    "SELECT t.tgname, c.relname, t.tgenabled::text, "
    "pg_catalog.pg_get_triggerdef(t.oid) FROM pg_catalog.pg_trigger t "
    "JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'cp_lane3' AND NOT t.tgisinternal"
)
_CONSTRAINTS_SQL: Final = (
    "SELECT c.relname || '.' || k.conname, pg_catalog.pg_get_constraintdef(k.oid) "
    "FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid = k.conrelid "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'cp_lane3'"
)
_INDEXES_SQL: Final = (
    "SELECT i.relname, pg_catalog.pg_get_indexdef(i.oid) FROM pg_catalog.pg_index x "
    "JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid "
    "JOIN pg_catalog.pg_class c ON c.oid = x.indrelid "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'cp_lane3'"
)
_RULES_SQL: Final = (
    "SELECT c.relname || '.' || r.rulename FROM pg_catalog.pg_rewrite r "
    "JOIN pg_catalog.pg_class c ON c.oid = r.ev_class "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'cp_lane3'"
)
_POLICIES_SQL: Final = (
    "SELECT c.relname || '.' || p.polname FROM pg_catalog.pg_policy p "
    "JOIN pg_catalog.pg_class c ON c.oid = p.polrelid "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = 'cp_lane3'"
)
_RLS_FLAGS_SQL: Final = (
    "SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
    "ON n.oid = c.relnamespace WHERE n.nspname = 'cp_lane3' AND c.relkind = 'r' "
    "AND (c.relrowsecurity OR c.relforcerowsecurity)"
)
#: How many DISTINCT owners the schema and everything in it has (must be one).
_OWNERS_SQL: Final = (
    "SELECT count(DISTINCT o) FROM ("
    "SELECT nspowner AS o FROM pg_catalog.pg_namespace WHERE nspname = 'cp_lane3' "
    "UNION ALL SELECT c.relowner FROM pg_catalog.pg_class c JOIN "
    "pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'cp_lane3' "
    "UNION ALL SELECT p.proowner FROM pg_catalog.pg_proc p JOIN "
    "pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'cp_lane3' "
    "UNION ALL SELECT t.typowner FROM pg_catalog.pg_type t JOIN "
    "pg_catalog.pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'cp_lane3'"
    ") owners"
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def acl_queries(migration_path: Path | None = None) -> dict[str, str]:
    """The five privilege read-back queries, READ FROM `v023_lane3_store`.

    One source: the migration runs them before it commits, and this runs the very
    same text afterwards. `migration_path` is for tests; production resolves the
    migration directory exactly as the migrator does (`vendor_cp.migrations`).
    """
    if migration_path is None:
        from vendor_cp.migrations import vendor_versions_dir

        migration_path = vendor_versions_dir() / _MIGRATION_FILE
    spec = importlib.util.spec_from_file_location(
        "v023_lane3_store_acl", migration_path
    )
    if spec is None or spec.loader is None:
        raise FileNotFoundError(_MIGRATION_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {name: str(getattr(module, name)) for name in ACL_QUERY_NAMES}


def _diff(
    kind: str, found: Mapping[str, str], expected: Mapping[str, str]
) -> list[str]:
    out: list[str] = []
    for name in sorted(set(found) | set(expected)):
        if name not in found:
            out.append(f"{kind}-missing:{name}")
        elif name not in expected:
            out.append(f"{kind}-unpinned:{name}")
        elif found[name] != expected[name]:
            out.append(f"{kind}-changed:{name}")
    return out


def check_store_integrity(
    execute: Callable[..., Any],
    *,
    functions: Mapping[str, str] | None = None,
    triggers: Mapping[str, tuple[str, str, str]] | None = None,
    migration_path: Path | None = None,
) -> tuple[str, ...]:
    """The violations, sorted; empty means the store is exactly as pinned.

    `execute(sql, params=None)` returns the rows of a read-only query. The pins
    default to this module's, and are parameters so a test can show the check
    refuses. A server that is not PostgreSQL 16 yields ONLY
    `repin-required:postgresql-<major>`: the digests are PG16 output.
    """
    expected_functions = FUNCTION_DEFINITION_SHA256 if functions is None else functions
    expected_triggers = TRIGGERS if triggers is None else triggers
    major = int(str(execute(_VERSION_SQL)[0][0])) // 10000
    if major != PINNED_MAJOR:
        return (f"repin-required:postgresql-{major}",)
    violations: list[str] = []

    violations += _diff(
        "function",
        {str(r[0]): _digest(str(r[1])) for r in execute(_FUNCTIONS_SQL)},
        expected_functions,
    )
    violations += _diff(
        "public-function",
        {
            str(r[0]): _digest(str(r[1]))
            for r in execute(_PUBLIC_FUNCTIONS_SQL, {"names": _PUBLIC_NAMES})
        },
        PUBLIC_FUNCTIONS,
    )
    violations += _diff(
        "constraint",
        {str(r[0]): _digest(str(r[1])) for r in execute(_CONSTRAINTS_SQL)},
        CONSTRAINTS,
    )
    violations += _diff(
        "index",
        {str(r[0]): _digest(str(r[1])) for r in execute(_INDEXES_SQL)},
        INDEXES,
    )
    violations += [f"rule-present:{r[0]}" for r in execute(_RULES_SQL)]
    violations += [f"rls-policy-present:{r[0]}" for r in execute(_POLICIES_SQL)]
    violations += [f"rls-enabled:{r[0]}" for r in execute(_RLS_FLAGS_SQL)]
    if int(execute(_OWNERS_SQL)[0][0]) != 1:
        violations.append("owner-not-single")
    for name, sql in acl_queries(migration_path).items():
        if int(execute(sql)[0][0]) != 0:
            violations.append(f"acl-leak:{name}")

    found_triggers = {
        str(row[0]): (str(row[1]), str(row[2]), _digest(str(row[3])))
        for row in execute(_TRIGGERS_SQL)
    }
    for name in sorted(set(found_triggers) | set(expected_triggers)):
        if name not in found_triggers:
            violations.append(f"trigger-missing:{name}")
        elif name not in expected_triggers:
            violations.append(f"trigger-unpinned:{name}")
        else:
            table, state, definition = found_triggers[name]
            want_table, want_state, want_definition = expected_triggers[name]
            if state != want_state:
                violations.append(f"trigger-not-enabled:{name}")
            if table != want_table or definition != want_definition:
                violations.append(f"trigger-changed:{name}")
    return tuple(sorted(violations))


def main(
    argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None
) -> int:
    del argv
    env = os.environ if environ is None else environ
    dsn = env.get(ADMIN_DSN_ENV, "").strip()
    if not dsn:
        print(
            f"store integrity refused: {ADMIN_DSN_ENV} is not supplied",
            file=sys.stderr,
        )
        return 2
    try:
        from dotmac_kernel.session_runtime import DatabaseRuntime

        session = DatabaseRuntime.from_urls(
            database_url=dsn, platform_database_url=dsn
        ).platform_session_factory()
        try:
            session.execute(text("SET TRANSACTION READ ONLY"))
            violations = check_store_integrity(
                lambda sql, params=None: session.execute(text(sql), params or {}).all()
            )
        finally:
            session.rollback()
            session.close()
    except Exception as error:  # noqa: BLE001 - class name only, never the text
        print(f"store integrity unverifiable: {type(error).__name__}", file=sys.stderr)
        return 2
    if violations:
        print("store integrity violated: " + ", ".join(violations), file=sys.stderr)
        return 3 if violations[0].startswith("repin-required") else 2
    print("store integrity passed")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
