from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import json
import os

from crypto_adapter import establish_session


app = FastAPI(title="QERIS Security Gateway", version="1.0.0")

# Enable CORS for browser frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_POLICY_PATH = os.path.join(_BASE_DIR, "policy.json")
_DEVICES_PATH = os.path.join(_BASE_DIR, "devices.json")
_LOGS_PATH = os.path.join(_BASE_DIR, "gateway_logs.jsonl")

# Load policy configuration
with open(_POLICY_PATH, "r") as file:
    policy = json.load(file)


# Load device capability registry
with open(_DEVICES_PATH, "r") as file:
    device_registry = json.load(file)


class FlowRequest(BaseModel):
    device_id: str
    flow_id: str
    requested_mode: str


class CryptoDemoRequest(BaseModel):
    device_id: str
    flow_id: str
    message: str


SECURITY_LEVEL = {
    "CLASSICAL": 1,
    "HYBRID": 2,
    "PQC": 3
}


def check_policy(flow_id, requested_mode):

    if flow_id not in policy:
        return False, "Unknown flow"

    if requested_mode not in SECURITY_LEVEL:
        return False, "Unknown security mode"

    required_mode = policy[flow_id]["minimum_mode"]

    required_level = SECURITY_LEVEL[required_mode]
    requested_level = SECURITY_LEVEL[requested_mode]

    if requested_level < required_level:
        return False, "Requested mode is below security floor"

    return True, "Policy satisfied"


def check_device_capability(device_id, requested_mode):

    if device_id not in device_registry:
        return False, "Unknown device"

    supported_modes = device_registry[device_id]["supported_modes"]

    if requested_mode not in supported_modes:
        return False, "Device does not support requested mode"

    return True, "Device capability satisfied"


def check_floor_feasibility(device_id, flow_id):

    if device_id not in device_registry:
        return False, "Unknown device"

    if flow_id not in policy:
        return False, "Unknown flow"

    required_mode = policy[flow_id]["minimum_mode"]
    required_level = SECURITY_LEVEL[required_mode]

    supported_modes = device_registry[device_id]["supported_modes"]

    highest_supported_level = max(
        SECURITY_LEVEL[mode]
        for mode in supported_modes
    )

    if highest_supported_level < required_level:
        return False, "Security floor is unreachable for this device"

    return True, "Security floor is reachable"


def write_log(
    device_id,
    flow_id,
    sensitivity,
    minimum_mode,
    requested_mode,
    policy_version,
    decision,
    reason
):

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "device_id": device_id,
        "flow_id": flow_id,
        "sensitivity": sensitivity,
        "minimum_mode": minimum_mode,
        "requested_mode": requested_mode,
        "policy_version": policy_version,
        "decision": decision,
        "reason": reason
    }

    with open(_LOGS_PATH, "a") as file:
        file.write(json.dumps(log_entry) + "\n")


@app.post("/check-flow")
def check_flow(request: FlowRequest):

    # First check whether the requested flow exists
    if request.flow_id not in policy:
        decision = "REJECT"
        reason = "Unknown flow"

    # Then check whether the device can ever satisfy the flow's floor
    else:
        floor_reachable, floor_reason = check_floor_feasibility(
            request.device_id,
            request.flow_id
        )

        if not floor_reachable:
            decision = "FLOOR_UNREACHABLE"
            reason = floor_reason

        else:
            # Check the requested security mode against the policy
            result, reason = check_policy(
                request.flow_id,
                request.requested_mode
            )

            if not result:
                decision = "REJECT"

            else:
                # Check whether the device actually supports the requested mode
                capability_result, capability_reason = check_device_capability(
                    request.device_id,
                    request.requested_mode
                )

                if not capability_result:
                    decision = "REJECT"
                    reason = capability_reason

                else:
                    decision = "ALLOW"
                    reason = "Policy and device capability satisfied"

    # Get trusted policy information
    if request.flow_id in policy:
        sensitivity = policy[request.flow_id]["sensitivity"]
        minimum_mode = policy[request.flow_id]["minimum_mode"]
        policy_version = policy[request.flow_id]["policy_version"]
        authority_id = policy[request.flow_id]["authority_id"]
    else:
        sensitivity = None
        minimum_mode = None
        policy_version = None
        authority_id = None

    # Write complete audit log
    write_log(
        request.device_id,
        request.flow_id,
        sensitivity,
        minimum_mode,
        request.requested_mode,
        policy_version,
        decision,
        reason
    )

    # Return gateway decision
    return {
        "flow_id": request.flow_id,
        "sensitivity": sensitivity,
        "minimum_mode": minimum_mode,
        "policy_version": policy_version,
        "authority_id": authority_id,
        "requested_mode": request.requested_mode,
        "decision": decision,
        "reason": reason
    }


@app.post("/crypto-demo")
def crypto_demo(request: CryptoDemoRequest):

    # The gateway must know the flow before creating a crypto session.
    if request.flow_id not in policy:
        return {
            "decision": "REJECT",
            "reason": "Unknown flow"
        }

    flow_policy = policy[request.flow_id]

    sensitivity = flow_policy["sensitivity"]
    minimum_mode = flow_policy["minimum_mode"]
    policy_version = flow_policy["policy_version"]

    try:
        # Establish the S1-backed crypto session.
        session = establish_session(
            device_id=request.device_id,
            flow_id=request.flow_id,
            sensitivity=sensitivity,
            policy_version=policy_version,
        )

        # Encrypt the message.
        encrypted = session.encrypt(
            request.message.encode("utf-8")
        )

        # Decrypt it again for the local round-trip demonstration.
        decrypted = session.decrypt(encrypted)

        return {
            "flow_id": request.flow_id,
            "sensitivity": sensitivity,
            "minimum_mode": minimum_mode,
            "policy_version": policy_version,
            "crypto": "ML-KEM + HKDF-SHA256 + AES-256-GCM",
            "decision": "ALLOW",
            "encrypted_message_length": len(encrypted),
            "decrypted_message": decrypted.decode("utf-8"),
        }

    except Exception as error:
        return {
            "flow_id": request.flow_id,
            "decision": "REJECT",
            "reason": f"Crypto integration failed: {str(error)}"
        }