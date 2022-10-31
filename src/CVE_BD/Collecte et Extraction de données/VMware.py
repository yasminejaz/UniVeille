import re
import requests
from Param import *
from datetime import datetime
from CVSS3 import cvss3_att_value


def VMware(cursor, connect):
    global cve_id, titre, date_publication, date_modification, source, description, cvss2_vector_string, \
        cvss2_access_vector, cvss2_access_complexity, cvss2_authentication, cvss2_confidentiality_impact, \
        cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, cvss2_severity, cvss2_exploit_score, \
        cvss2_impact_score, cvss2_obtain_all_priv, cvss2_obtain_user_priv, cvss2_obtain_other_priv, \
        cvss2_user_interaction, cvss3_vector_string, cvss3_attack_vector, cvss3_attack_complexity, cvss3_priv_required, \
        cvss3_user_interaction, cvss3_scope, cvss3_severity, cvss3_confidentiality_impact, cvss3_integrity_impact, \
        cvss3_availibility_impact, cvss3_score, cvss3_exploit_score, cvss3_impact_score

    url = "https://www.vmware.com/api/vmsa.html"
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    data = response.json()

    for info in data['advisories']:
        if "responsematrix" in info and "creationdate" in info and ('synopsis' in info or 'decription' in info):
            for cvss in info['responsematrix']:
                for cve in list(cvss['CVE-identifier'].split(",")):
                    if cve != 'N/A':
                        cve_id = re.sub("(.*)(CVE)", r"\2", cve)
                        source="VMware"
                        if cvss['severity'] != 'na':
                            cvss3_severity = cvss['severity']
                            cvss3_score = re.sub(",.*|-.*", "", cvss['CVSSv3'])
                            if "CVSSv3-url" in cvss:
                                if cvss['CVSSv3-url'] != 'N/A':
                                    cvss3_vector_string = re.sub('.*CVSS:3.0/', "", cvss['CVSSv3-url'])
                        date_publication = datetime.strptime(info['creationdate'], "%B %d, %Y").date()
                        if "updatedate" in info:
                            date_modification = datetime.strptime(info['updatedate'], "%B %d, %Y").date()
                        if "synopsis" in info:
                            description = info['synopsis']
                        elif 'description' in info:
                            description = info['description']
                        cvss3_attack_vector, cvss3_attack_cpmplexity, cvss3_priv_required, cvss3_user_interaction, cvss3_scope, cvss3_confidentiality_impact, cvss3_integrity_impact, cvss3_availibility_impact = cvss3_att_value(cvss3_vector_string)
                        v1 = re.search("([\w.-]*)\s?([\s\w.-]*)", cvss["product"])
                        if v1.group(1) == "Vmware":
                            vendor = v1.group(1)

                            product = v1.group(2).strip()
                        else:
                            vendor = "VMware"
                            product = v1.group(1).strip() + " " + v1.group(2).strip()
                        for ver in cvss["version"].split(","):
                            if ver == "Any":
                                version = "*"
                            else:
                                version = ver
                            cpe = "cpe:2.3:-:" + vendor + ":" + product.replace(" ", "_") + ":" + version
                            cursor.execute(""" INSERT INTO produit(cpe, vendor, product, version, versionstartincluding, 
                                                                    versionendincluding, versionstartexcluding, versionendexcluding, cve_id)
                                                                                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                                                                        ON CONFLICT (cpe, cve_id) DO NOTHING""",
                                           (cpe, vendor, product, version, versionStartIncluding,
                                            versionEndIncluding,
                                            versionStartExcluding, versionEndExcluding, cve_id))
                            connect.commit()
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

    last = datetime.now().strftime("%Y-%m-%d")
    query = """Update lastupdate SET last_update =%s 
                    WHERE source =%s"""
    cursor.execute(query, (last, 'VMware'))
    connect.commit()
    print("VMware update is done")