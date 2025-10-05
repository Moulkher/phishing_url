from GSB_checker import gsb_checker
from ssl_checker import ssl_checker
from whois_info import get_whois_info


# Function that can be added
# extract features, look into heuristics for fake emails and add sources

def normalize_url(u):
    """check and normalize input"""
    u = u.strip()
    if not u:
        return {"ok": False, "error": "invalid URL"}
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return {"ok": True, "clean":u} 


    
if __name__ == "__main__":
    print("#"*40)
    url = input("Input URL to be tested : ")
   
    err_log = []
    n = normalize_url(url)
    while (not n.get('ok')):
        print("URL string empty. Let's try again :")  
        url = input("Input URL to be tested : ")
        n = normalize_url(url)


    

    # Check the google safe browsing database
    print("#"*40)
    print("#"*20,"Checking Google safe browing","#"*20) 
    res_gsb = gsb_checker(n.get('clean'))

    # Check whois
    print("#"*20,"Checking Domain Info","#"*20) 
    res_whois = get_whois_info(n.get("clean"))
    # Check SSL/TLS
    print("#"*20,"Checking SSL/TLS Info","#"*20) 
    res_ssl = ssl_checker(n.get('clean'))
    print("#"*40)
    print("#"*20,"RESULTS","#"*20) 
    if (not res_gsb.get("ok")):
        err_log.append(f"Error from the GSB checker : {res_gsb.get("error")}")
    else :
        print(f"Detected as malicious from Google safe browsing, Type : {res_gsb.get('threat_type')} ------- " if res_gsb.get('malicious') else "Not flagued in Google safe browsing")
    
    if not res_whois.get("ok"):
            err_log.append(res_whois.get("error"))
    else :
        print(f"Risks detected from the domain lookup : {res_whois.get("risk_flags")} "if res_whois.get("risk_flags") else "No risk  detected in the domain lookup")
    if not res_ssl.get("ok"):
            err_log.append(res_ssl.get("error"))
    else :
        print(f"Risks detected from the SSL/TLS lookup : {res_ssl.get("risk_flags")} "if res_ssl.get("risk_flags") else "No risk  detected in the domain lookup")
    
    if err_log:
         for i in err_log:
              print(i)