import requests


gateway_url = "http://127.0.0.1:8000/check-flow"


def send_request(flow_id, requested_mode):

    data = {
    "device_id": "device_003",
    "flow_id": flow_id,
    "requested_mode": requested_mode
    }
    response = requests.post(
        gateway_url,
        json=data
    )

    print("Gateway response:")
    print(response.json())
    print()


send_request(
    "emergency_stop",
    "CLASSICAL"
)

send_request(
    "emergency_stop",
    "HYBRID"
)

send_request(
    "temperature_01",
    "CLASSICAL"
)

send_request(
    "emergency_stop",
    "CLASSICAL"
)

send_request(
    "emergency_stop",
    "HYBRID"
)

send_request(
    "temperature_01",
    "CLASSICAL"
)

send_request(
    "temperature_01",
    "PQC"
)