import json

def create_ticket(ticket_type, description, host, dry_run=True):
    """
    Create a ticket in the ServiceDesk system (mocked).

    Args:
        ticket_type (str): e.g., "SDM"
        description (str): Description of the ticket
        host (str): Host where the event occurred
        dry_run (bool): If True, prints payload instead of sending API request
    """
    payload = {
        "ticket_type": ticket_type,
        "description": description,
        "host": host
    }

    if dry_run:
        print(f"[MOCK API CALL] Sending ticket: {json.dumps(payload)}")
    else:
        # Uncomment and configure the real API call
        # import requests
        # url = "https://loop.example.com/api/tickets"
        # headers = {"Authorization": "Bearer YOUR_API_KEY", "Content-Type": "application/json"}
        # response = requests.post(url, headers=headers, json=payload)
        # if response.status_code == 201:
        #     print(f"Ticket created successfully: {response.json()}")
        # else:
        #     print(f"Failed to create ticket: {response.status_code}, {response.text}")
        pass

def process_triggered_alerts(alerts, rule_dict=None):
    """
    Process a list of triggered alerts and create tickets via ServiceDesk API.

    Args:
        alerts (list of dict): Each alert dict should contain:
            - 'ticket_type': SDM type
            - 'description': Alert description
            - 'host': Host affected
        rule_dict (dict, optional): Optional mapping for extra logic
    """
    for alert in alerts:
        ticket_type = alert.get("ticket_type", "SDM")
        description = alert.get("description", "No description")
        host = alert.get("host", "Unknown")
        create_ticket(ticket_type, description, host)