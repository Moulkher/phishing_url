import os
from dotenv import load_dotenv
import requests

load_dotenv()
API_KEY = os.getenv("GSB_KEY")
GSB_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"


def gsb_checker(url):
    if not API_KEY:
        return {"ok": False, "error": "Missing API key"}

    payload = {
        "client": {
            "clientId": "is-it-phishy",    
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [ #scan for all treatTypes
                "MALWARE",
                "SOCIAL_ENGINEERING",    # phishing
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        r = requests.post(GSB_URL, json=payload, timeout=10, headers={"User-Agent": "PhishDetectTool/1.0"})
    except requests.RequestException as e:
        return {"ok": False, "error": f"Request error: {e}"}

    # return status + body if status code not ok
    if r.status_code != 200:
        return {"ok": False, "error": "status : {r.status_code}, body : {r.text}"}

    data = r.json()
    # Google returns {} if no matches
    matches = data.get("matches", [])
    threat_type = "none"
    if bool(matches):
        threat_type = matches[0].get("threatType")
    return {"ok": True, "malicious": bool(matches), "threat_type": threat_type}

#if __name__ == "__main__":
    print(check_url("www.testsafebrowsing.appspot.com/s/malware.html"))
    print(check_url("www.cloud.google.com/web-risk/docs?hl=fr"))
    print(check_url("https://ferromittal.com/?gad_source=1	"))
    


