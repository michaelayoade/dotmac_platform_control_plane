"""Synthetic final-file joins for loader fixtures; never native evidence.

The binder composition test does not use this final-file writer: it consumes
only the prelaunch inputs and invokes the real production root binder.
"""

from copy import deepcopy

from vendor_cp.deployment.gate0_framing import canonical
from vendor_cp.deployment.gate0_runner_installation import (
    _a9_static_selection_digest,
    _hash,
)
from vendor_cp.deployment.gate0_runner_tokens import (
    _SUPPLIER_AMENDMENT,
    _SUPPLIER_METHOD,
    _SUPPLIER_SOURCE,
)


def synthetic_a9_join(collection, bootstrap, files, pin, *, binding_digest=None):
    root = "/run/dotmac-gate0-collector"
    lifecycle_binding = binding_digest or "sha256:" + "c" * 64
    campaign = collection["campaign_digest"]
    originals = deepcopy(
        collection.get(
            "broker",
            dict(origin="https://broker.example", path="/opaque", query="key=value"),
        )
    )
    template = {
        k: deepcopy(v)
        for k, v in collection.items()
        if k
        not in (
            "broker",
            "qualification",
            "prelaunch",
            "job_broker_binding",
            "binding_marker",
        )
    }
    template["schema"] = "Gate0RunnerCollectionTemplate.v1"
    btemplate = {
        k: deepcopy(v)
        for k, v in bootstrap.items()
        if k
        not in (
            "collection_installation",
            "qualification",
            "prelaunch",
            "job_broker_binding",
            "binding_marker",
        )
    }
    btemplate["schema"] = "Gate0CollectorBootstrapTemplate.v1"
    policy = dict(
        schema="Gate0A9BrokerPolicy.v1",
        method=_SUPPLIER_METHOD,
        amendment_digest=_SUPPLIER_AMENDMENT,
        supplier_commit=_SUPPLIER_SOURCE,
        origins=[originals["origin"]],
        profile={},
    )
    prelaunch = dict(
        schema="Gate0A9PrelaunchSelection.v1",
        lifecycle_binding_digest=lifecycle_binding,
        campaign_digest=campaign,
        collection_template=pin(
            root + "/collection-template.json", canonical(template)
        ),
        bootstrap_template=pin(root + "/bootstrap-template.json", canonical(btemplate)),
        broker_policy=pin(root + "/broker-policy.json", canonical(policy)),
    )
    runtime = dict(
        manager_identity=dict(
            executable_digest="sha256:" + "1" * 64,
            version="synthetic",
            kernel_release="synthetic",
            boot_id="00000000-0000-0000-0000-000000000001",
        )
    )
    for role in ("collection", "bootstrap"):
        native_pin = bootstrap.get("native_receipt") if role == "bootstrap" else None
        native_pin = native_pin or pin(
            root + "/" + role + "-native.json", b"SYNTHETIC-NATIVE-BOUNDARY"
        )
        qualification = dict(
            schema="Gate0A9StaticNativeQualification.v1",
            role=role,
            lifecycle_binding_digest=lifecycle_binding,
            campaign_digest=campaign,
            prelaunch_selection_digest=_a9_static_selection_digest(prelaunch),
            template_digest=prelaunch[role + "_template"]["digest"],
            broker_policy_digest=prelaunch["broker_policy"]["digest"],
            runtime_identity=runtime,
            native_receipt=native_pin,
        )
        prelaunch[role + "_native_qualification"] = pin(
            root + "/" + role + "-native-qualification.json", canonical(qualification)
        )
    # The digest excludes exactly the two native pins, so both role records
    # share the same static selection domain before/after pins are attached.
    prelaunch_raw = canonical(prelaunch)
    files[root + "/lifecycle/prelaunch.json"] = prelaunch_raw
    prelaunch_pin = pin(root + "/a9-prelaunch.json", prelaunch_raw)
    job = collection["job"]
    selected = dict(
        repository_id=int(job["repository_id"]),
        owner_id=int(job["repository_owner_id"]),
        run_id=int(job["run_id"]),
        attempt=int(job["run_attempt"]),
        workflow_id=1,
        source_revision=job["workflow_sha"],
        environment_id=1,
        job_id=2,
        job_name="synthetic",
        runner_id=3,
        runner_name=job["runner_name"],
        runner_group_id=int(job["runner_group_id"]),
    )
    binding = dict(
        schema="Gate0A9JobBrokerBinding.v1",
        lifecycle_binding_digest=lifecycle_binding,
        campaign_digest=campaign,
        prelaunch_digest=_hash(prelaunch_raw),
        broker_policy_digest=prelaunch["broker_policy"]["digest"],
        static_native_qualification_digests={
            r: prelaunch[r + "_native_qualification"]["digest"]
            for r in ("collection", "bootstrap")
        },
        boot_id="00000000-0000-0000-0000-000000000001",
        jit_invocation_id="a" * 32,
        selected_job_coordinates=selected,
        github_observation_digest="sha256:" + "2" * 64,
        courier_pid=3,
        courier_start="4",
        origin=originals["origin"],
        path=originals["path"],
        query=originals["query"],
        original_provisioning_end=123456.0,
    )
    binding_pin = pin(root + "/job-broker-binding.json", canonical(binding))
    marker_path = root + "/job-broker-binding-complete.json"
    for role, doc in (("collection", collection), ("bootstrap", bootstrap)):
        doc.update(
            prelaunch=prelaunch_pin,
            job_broker_binding=binding_pin,
            binding_marker=marker_path,
        )
        doc.pop("qualification", None)
        doc["schema"] = (
            "Gate0RunnerCollectionInstallation.v2"
            if role == "collection"
            else "Gate0CollectorBootstrapInstallation.v3"
        )
        if role == "collection":
            doc["broker"] = {k: originals[k] for k in ("origin", "path", "query")}
            doc["broker"]["qualification"] = binding_pin
        else:
            doc["collection_installation"] = dict(
                path=root + "/installation.json",
                digest=_hash(files[root + "/installation.json"]),
            )
        qualification = dict(
            schema="Gate0A9DerivedInstallationQualification.v1",
            role=role,
            template_digest=prelaunch[role + "_template"]["digest"],
            static_native_qualification_digest=prelaunch[
                role + "_native_qualification"
            ]["digest"],
            job_broker_binding_digest=binding_pin["digest"],
            installation_digest=_hash(canonical(doc)),
        )
        doc["qualification"] = pin(
            root + "/" + role + "-qualification.json", canonical(qualification)
        )
        files[
            root + ("/installation.json" if role == "collection" else "/bootstrap.json")
        ] = canonical(doc)
    pin(
        marker_path,
        canonical(
            dict(
                schema="Gate0A9JobBrokerBindingComplete.v1",
                prelaunch_digest=_hash(prelaunch_raw),
                collection_digest=_hash(files[root + "/installation.json"]),
                bootstrap_digest=_hash(files[root + "/bootstrap.json"]),
                binding_digest=binding_pin["digest"],
            )
        ),
    )
    return prelaunch, binding
