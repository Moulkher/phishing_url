from datetime import datetime, timezone, timedelta
import whois


def normalize_dt(dt):
    """ensure datetime is in UTC""" 
    if dt is None:
        return None
    
    if isinstance(dt, list):
        dt = dt[-1]

    if dt.tzinfo is None:  # naive
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

"""
def get_whois_info(url) : 
    try :
        w = whois.whois(url)
        return {"ok": True,
                "creation_date": w.creation_date,
                "expiration_date": w.expiration_date
        }
        
    except Exception as e:
        return {"ok": False,
                "error": f"Error fetching WHOIS info: {e}"}
    
"""    


def get_whois_info(url) : 
    """check domain age and provide risk results"""

    result = {
        "ok":True,
        "creation_date": None,
        "expiration_date":None,
        "risk_flags": [],
        "error": None
    }

    try :
        w = whois.whois(url)

        create = normalize_dt(w.creation_date)
        expire = normalize_dt(w.expiration_date)

        result["creation_date"] = create
        result["expiration_date"] = expire
        
        # compare to current date
        if expire and create :
            now = datetime.now(timezone.utc)
            if (now - create).days < 90:
                    result["risk_flags"].append("domain_created_recently")

            if 364 <= (expire - create).days <= 366:
                   result["risk_flags"].append("domain_with_one_year_validity")
    except Exception as e:
        result["ok"] = False
        result["error"] = f"Error fetching WHOIS info: {e}"
    
    return result

#print(get_whois_info("https://h2bet-jogos.com"))