window.SIEM_DATA = {
  "generated": "2026-10-29 00:26",
  "summary": {
    "total_events": 31,
    "unique_ips": 5,
    "high_risk": 2,
    "medium_risk": 1,
    "low_risk": 3
  },
  "attack_types": {
    "SQL injection": 3,
    "XSS": 2,
    "Path traversal": 1,
    "Scanner": 1,
    "Brute force": 1
  },
  "top_ips": [
    {
      "ip": "10.0.0.66",
      "risk_score": 100,
      "risk_level": "HIGH"
    },
    {
      "ip": "192.168.1.50",
      "risk_score": 75,
      "risk_level": "HIGH"
    },
    {
      "ip": "10.0.0.25",
      "risk_score": 30,
      "risk_level": "MEDIUM"
    },
    {
      "ip": "192.168.1.10",
      "risk_score": 0,
      "risk_level": "LOW"
    },
    {
      "ip": "192.168.1.10",
      "risk_score": 0,
      "risk_level": "LOW"
    },
    {
      "ip": "192.168.1.22",
      "risk_score": 0,
      "risk_level": "LOW"
    }
  ],
  "timeline": [
    {
      "time": "01:06",
      "count": 17
    },
    {
      "time": "08:15",
      "count": 5
    },
    {
      "time": "09:03",
      "count": 1
    },
    {
      "time": "09:04",
      "count": 1
    }
  ],
  "findings": [
    {
      "ip": "10.0.0.66",
      "source": "Web",
      "detail": "SQLi x3, XSS x2, traversal x1, scanner, scanning",
      "risk_score": 100,
      "risk_level": "HIGH"
    },
    {
      "ip": "192.168.1.50",
      "source": "Innlogging",
      "detail": "5 mislykkede innlogginger (brute force)",
      "risk_score": 75,
      "risk_level": "HIGH"
    },
    {
      "ip": "10.0.0.25",
      "source": "Innlogging",
      "detail": "2 mislykkede innlogginger",
      "risk_score": 30,
      "risk_level": "MEDIUM"
    },
    {
      "ip": "192.168.1.10",
      "source": "Innlogging",
      "detail": "0 mislykkede innlogginger",
      "risk_score": 0,
      "risk_level": "LOW"
    },
    {
      "ip": "192.168.1.10",
      "source": "Web",
      "detail": "3 foresp\u00f8rsler",
      "risk_score": 0,
      "risk_level": "LOW"
    },
    {
      "ip": "192.168.1.22",
      "source": "Web",
      "detail": "1 foresp\u00f8rsler",
      "risk_score": 0,
      "risk_level": "LOW"
    }
  ]
};
