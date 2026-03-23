# 03/23/26 Leighton Cook | Security Event Dictionary Rules |  

rule_dictionary = {
    "AuthenticationFailed": {
        "action": "aggregate",
        "severity": "High",
        "threshold": 3,  # e.g., 3 failed logins → trigger event
        "ticket_type": "SDM"
    },
    "BadAPIToken": {
        "action": "alert",
        "severity": "Critical",
        "ticket_type": "SDM"
    },
    "MalwareDetected": {
        "action": "notify",
        "severity": "Critical"
    }
}