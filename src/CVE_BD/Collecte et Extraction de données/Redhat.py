import re
from datetime import datetime

import requests
from Param import *
from CVSS3 import cvss3_att_value


def Redhat(startDate, cursor, connect):
    global cve_id, titre, date_publication, date_modification, source, description, cvss2_vector_string, \
        cvss2_access_vector, cvss2_access_complexity, cvss2_authentication, cvss2_confidentiality_impact, \
        cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, cvss2_severity, cvss2_exploit_score, \
        cvss2_impact_score, cvss2_obtain_all_priv, cvss2_obtain_user_priv, cvss2_obtain_other_priv, \
        cvss2_user_interaction, cvss3_vector_string, cvss3_attack_vector, cvss3_attack_complexity, cvss3_priv_required, \
        cvss3_user_interaction, cvss3_scope, cvss3_severity, cvss3_confidentiality_impact, cvss3_integrity_impact, \
        cvss3_availibility_impact, cvss3_score, cvss3_exploit_score, cvss3_impact_score

    url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=1000&after={startDate}"
    response = requests.get(url)
    data = response.json()
    if data:
        for cve in data:
            cve_id = cve['CVE']
            titre = cve['bugzilla_description']
            source = "Redhat Advisory"
            description = cve['bugzilla_description']
            if cve['public_date']:
                date_publication = re.sub("T.*", "", cve['public_date'])
            if "cvss3_scoring_vector" in cve:
                cvss3_vector_string = cve['cvss3_scoring_vector']
            if "cvss3_score" in cve:
                cvss3_score = cve["cvss3_score"]
            cvss3_severity = cve['severity']
            cvss3_attack_vector, cvss3_attack_complexity, cvss3_priv_required, cvss3_user_interaction, \
            cvss3_scope, cvss3_confidentiality_impact, cvss3_integrity_impact, \
            cvss3_availibility_impact = cvss3_att_value(cvss3_vector_string)

            cursor.execute("""INSERT INTO cve (cve_id, titre, description, source, date_publication, date_modification, cvss3_vector_string, cvss3_score,
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
                           (cve_id, titre, description, source,date_publication, date_modification,
                            cvss3_vector_string, cvss3_score,cvss3_severity, cvss3_attack_vector,
                            cvss3_attack_complexity, cvss3_priv_required, cvss3_user_interaction,
                            cvss3_scope, cvss3_confidentiality_impact, cvss3_integrity_impact,
                            cvss3_availibility_impact, cvss2_vector_string, cvss2_access_vector,
                            cvss2_access_complexity, cvss2_authentication, cvss2_confidentiality_impact,
                            cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, cvss2_severity,
                            cvss2_exploit_score, cvss2_impact_score, cvss2_obtain_all_priv,
                            cvss2_obtain_user_priv, cvss2_obtain_other_priv, cvss2_user_interaction)
                           )
            connect.commit()
            cwe_id = cve['CWE']
            if cwe_id:
                cwes = re.sub('[>|()]', ' ', cwe_id).replace("- ", ' ').split(" ")
                for id in cwes:
                    if id:
                        cursor.execute("""INSERT INTO cve_cwe (cve_id, cwe_id)
                                        VALUES (%s, %s) ON CONFLICT (cve_id,cwe_id) DO NOTHING """,
                                       (cve_id, id)
                                       )
                        connect.commit()

            url = cve["resource_url"]
            cursor.execute("""INSERT INTO reference (cve_id, url)
                                                    VALUES (%s, %s) ON CONFLICT (cve_id,url) DO NOTHING
                                            """,
                           (cve_id, url)
                           )
            connect.commit()

            for prod in cve['affected_packages']:
                prod = prod.split(":")
                cpe = "cpe:2.3:-:-:"+prod[0]+":"+prod[1]
                cursor.execute(""" INSERT INTO produit(cpe, vendor, product, version, versionstartincluding, 
                                versionendincluding, versionstartexcluding, versionendexcluding, cve_id)
                                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                                    ON CONFLICT (cpe, cve_id) DO NOTHING""",
                               (cpe, vendor, prod[0], prod[1], versionStartIncluding, versionEndIncluding,
                                versionStartExcluding, versionEndExcluding, cve_id))
                connect.commit()

    last = datetime.now().strftime("%Y-%m-%d")
    query = """Update lastupdate SET last_update =%s 
                WHERE source =%s"""
    cursor.execute(query, (last, 'Redhat'))
    connect.commit()
    print("Redhat is done")
