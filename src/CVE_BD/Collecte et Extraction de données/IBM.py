import re
from base64 import b64encode
from datetime import datetime
import requests
import json
from Param import *
from CVSS3 import cvss3_att_value, cvss3severity


def IBM(startdate, cursor, connect, ):
    apikey = "60b229bf-1291-42d9-88d8-80166fb53dd9"
    apipwd = "122e8555-3ee8-4891-9547-463d52ed0d0a"

    token = b64encode((apikey + ":" + apipwd).encode(encoding='utf_8'))
    headers = {'Authorization': 'Basic ' + token.decode(), 'Accept': 'application/json'}

    url = f"https://api.xforce.ibmcloud.com:443/vulnerabilities?limit=200&startDate={startdate}"
    response = requests.get(url, headers=headers)

    global cve_id, titre, date_publication, date_modification, source, description, cvss2_vector_string, \
        cvss2_access_vector, cvss2_access_complexity, cvss2_authentication, cvss2_confidentiality_impact, \
        cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, cvss2_severity, cvss2_exploit_score, \
        cvss2_impact_score, cvss2_obtain_all_priv, cvss2_obtain_user_priv, cvss2_obtain_other_priv, \
        cvss2_user_interaction, cvss3_vector_string, cvss3_attack_vector, cvss3_attack_complexity, cvss3_priv_required, \
        cvss3_user_interaction, cvss3_scope, cvss3_severity, cvss3_confidentiality_impact, cvss3_integrity_impact, \
        cvss3_availibility_impact, cvss3_score, cvss3_exploit_score, cvss3_impact_score
    data = response.json()["rows"]
    for cve in data:
        if "stdcode" in cve:

            for id in cve['stdcode']:
                cve_id = id
                titre = cve["title"]
                description = cve["description"]
                source = "IBM"
                date_publication = re.sub("T.*", "", cve["reported"])
                cvss3_score = cve["risk_level"]
                cvss3_severity = cvss3severity(cvss3_score)
                cvss3_attack_vector = cve["cvss"]["access_vector"]
                cvss3_attack_complexity = cve["cvss"]["access_complexity"]
                cvss3_priv_required = cve["cvss"]["privilegesrequired"]
                cvss3_user_interaction = cve["cvss"]["userinteraction"]
                cvss3_scope = cve["cvss"]["scope"]
                cvss3_confidentiality_impact = cve["cvss"]["confidentiality_impact"]
                cvss3_integrity_impact = cve["cvss"]["integrity_impact"]
                cvss3_availibility_impact = cve["cvss"]["availability_impact"]

                cursor.execute("""INSERT INTO cve (cve_id, titre, description, source, date_publication, date_modification, 
                        cvss3_vector_string, cvss3_score,
                        cvss3_severity, cvss3_attack_vector, cvss3_attack_complexity, cvss3_priv_required, cvss3_user_interaction, \
                        cvss3_scope, cvss3_confidentiality_impact, cvss3_integrity_impact, cvss3_availibility_impact,cvss2_vector_string, \
                        cvss2_access_vector, cvss2_access_complexity, cvss2_authentication, cvss2_confidentiality_impact, \
                        cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, cvss2_severity, cvss2_exploit_score, \
                        cvss2_impact_score, cvss2_obtain_all_priv, cvss2_obtain_user_priv, cvss2_obtain_other_priv, \
                        cvss2_user_interaction)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                ON Conflict (cve_id) DO Update SET titre = coalesce (cve.titre, excluded.titre),
                                       description = coalesce (cve.description, excluded.description),
                                       source = coalesce (cve.source, excluded.source),
                                       date_publication = coalesce (cve.date_publication, excluded.date_publication),
                                       date_modification = coalesce (cve.date_modification, excluded.date_modification),
                                       cvss3_vector_string = coalesce (cve.cvss3_vector_string, excluded.cvss3_vector_string),
                                       cvss3_score = coalesce (cve.cvss3_score, excluded.cvss3_score),
                                       cvss3_severity = coalesce (cve.cvss3_severity, excluded.cvss3_severity),
                                       cvss3_attack_vector = coalesce (cve.cvss3_attack_vector, excluded.cvss3_attack_vector),
                                       cvss3_attack_complexity = coalesce (cve.cvss3_attack_complexity, excluded.cvss3_attack_complexity),
                                       cvss3_priv_required = coalesce (cve.cvss3_priv_required, excluded.cvss3_priv_required),
                                       cvss3_user_interaction = coalesce (cve.cvss3_user_interaction, excluded.cvss3_user_interaction),
                                       cvss3_scope = coalesce (cve.cvss3_scope, excluded.cvss3_scope),
                                       cvss3_confidentiality_impact = coalesce (cve.cvss3_confidentiality_impact, excluded.cvss3_confidentiality_impact),
                                       cvss3_integrity_impact = coalesce (cve.cvss3_integrity_impact, excluded.cvss3_integrity_impact),
                                       cvss3_availibility_impact = coalesce (cve.cvss3_availibility_impact, excluded.cvss3_availibility_impact),
                                       cvss2_vector_string = coalesce (cve.cvss2_vector_string, excluded.cvss2_vector_string),
                                       cvss2_access_vector= coalesce (cve.cvss2_access_vector, excluded.cvss2_access_vector),
                                       cvss2_access_complexity = coalesce (cve.cvss2_access_complexity, excluded.cvss2_access_complexity),
                                       cvss2_authentication = coalesce (cve.cvss2_authentication,excluded.cvss2_authentication),
                                       cvss2_confidentiality_impact = coalesce (cve.cvss2_confidentiality_impact, excluded.cvss2_confidentiality_impact),
                                       cvss2_integrity_impact = coalesce (cve.cvss2_integrity_impact, excluded.cvss2_integrity_impact),
                                       cvss2_availibility_impact = coalesce (cve.cvss2_availibility_impact, excluded.cvss2_availibility_impact),
                                       cvss2_score = coalesce (cve.cvss2_score, excluded.cvss2_score),
                                       cvss2_severity = coalesce (cve.cvss2_severity, excluded.cvss2_severity),
                                       cvss2_exploit_score = coalesce (cve.cvss2_exploit_score, excluded.cvss2_exploit_score),
                                       cvss2_impact_score = coalesce (cve.cvss2_impact_score, excluded.cvss2_impact_score),
                                       cvss2_obtain_all_priv = coalesce (cve.cvss2_obtain_all_priv, excluded.cvss2_obtain_all_priv),
                                       cvss2_obtain_user_priv = coalesce (cve.cvss2_obtain_user_priv, excluded.cvss2_obtain_user_priv),
                                       cvss2_obtain_other_priv = coalesce (cve.cvss2_obtain_other_priv, excluded.cvss2_obtain_other_priv),
                                       cvss2_user_interaction = coalesce (cve.cvss2_user_interaction, excluded.cvss2_user_interaction)
                                       """,
                               (cve_id, titre, description, source, date_publication, date_modification,
                                cvss3_vector_string, cvss3_score, cvss3_severity, cvss3_attack_vector,
                                cvss3_attack_complexity, cvss3_priv_required, cvss3_user_interaction,
                                cvss3_scope, cvss3_confidentiality_impact, cvss3_integrity_impact,
                                cvss3_availibility_impact, cvss2_vector_string, cvss2_access_vector,
                                cvss2_access_complexity, cvss2_authentication, cvss2_confidentiality_impact,
                                cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, cvss2_severity,
                                cvss2_exploit_score, cvss2_impact_score, cvss2_obtain_all_priv,
                                cvss2_obtain_user_priv, cvss2_obtain_other_priv, cvss2_user_interaction)
                               )
                connect.commit()
                for ref in cve['references']:
                    url = ref['link_target']

                    cursor.execute("""INSERT INTO reference (cve_id, url)
                                        VALUES (%s, %s) ON CONFLICT (cve_id,url) DO NOTHING
                                """,
                                   (cve_id, url)
                                   )
                    connect.commit()

                for prod in cve["platforms_affected"]:

                    info = re.search("([\w.-]*)\s([\sa-zA-Z-._]*)\s?([\w.-]*)", prod)
                    vendor = info.group(1)
                    product = info.group(2)
                    version = info.group(3)
                    cpe = "cpe:2.3:-:" + vendor + ":" + product + ":" + version
                    cursor.execute(""" INSERT INTO produit(cpe, vendor, product, version, versionstartincluding, 
                                        versionendincluding, versionstartexcluding, versionendexcluding, cve_id)
                                                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                                            ON CONFLICT (cpe, cve_id) DO NOTHING""",
                                   (cpe, vendor, product, version, versionStartIncluding,
                                    versionEndIncluding,
                                    versionStartExcluding, versionEndExcluding, cve_id))
                    connect.commit()

    last = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    query = """Update lastupdate SET last_update =%s 
            WHERE source =%s"""
    cursor.execute(query, (last, 'IBM'))
    connect.commit()
    print("IBM update done")
