import re
from datetime import datetime
import requests
from Param import *

from CVSS3 import cvss3_att_value, cvss3severity


def MSC(cursor, connect):

    global source, cvss3_vector_string, cvss3_score, cvss3_severity, cvss3_attack_vector, cvss3_attack_complexity, cvss3_scope, cvss3_user_interaction, cvss3_availibility_impact, cvss3_confidentiality_impact, cvss3_integrity_impact, cvss3_priv_required, threat, tag
    mydate = datetime.now()
    year = str(mydate.year)
    month = datetime.strptime(str(mydate.month), "%m").strftime("%b")
    Date = year+"-"+month
    url = f"https://api.msrc.microsoft.com/cvrf/v2.0/cvrf/{Date}"
    response = requests.get(url, headers={'Content-type': 'application/json', 'Accept': 'text/json'})
    data = response.json()

    products = []

    for vuln in data['Vulnerability']:
        cve_id = vuln['CVE']
        titre =vuln['Title']["Value"]
        for n in vuln['Notes']:
            if n['Type'] == 7:  # tag
                tag = n['Value']
            if n['Type'] == 8:  # CNA / source
                source = n['Value']

        if "Value" in vuln['Threats'][0]['Description']:
            threat = vuln['Threats'][0]['Description']['Value']

        if vuln['CVSSScoreSets']:
            cvss3_vector_string = re.sub('CVSS:3.1/', '', vuln['CVSSScoreSets'][0]['Vector'])

            cvss3_score = vuln['CVSSScoreSets'][0]['BaseScore']
            cvss3_severity = cvss3severity(cvss3_score)
            cvss3_attack_vector, cvss3_attack_complexity, cvss3_priv_required, cvss3_user_interaction, \
            cvss3_scope, cvss3_confidentiality_impact, cvss3_integrity_impact, \
            cvss3_availibility_impact = cvss3_att_value(cvss3_vector_string)

        for id in vuln['ProductStatuses'][0]['ProductID']:  # produit
            for p in data["ProductTree"]['FullProductName']:
                if p['ProductID'] == id:
                    products.append(p['Value'])
                    v1 = re.sub("for .*| to .*", "", p['Value'])
                    v2 = re.sub("\(.*\)", "", v1)
                    vendor = "Microsoft"
                    if "Version" in v2:
                        v3 = re.search("([\w\s._]*),?\sVersion\s([\w.-]*)", v2)
                        cpe = "cpe:-:Microsoft:" + v3.group(1).replace(" ", "_") + ":" + v3.group(2)
                        product = v3.group(1).replace(" ", "_")
                        version = v3.group(2)
                    elif "version" in v2:
                        v3 = re.search("([\w\s._]*),?\sversion\s([\w.-]*)", v2)
                        cpe = "cpe:-:Microsoft:" + v3.group(1).replace(" ", "_") + ":" + v3.group(2)
                        product = v3.group(1).replace(" ", "_")
                        version = v3.group(2)
                    else:
                        v3 = re.search("([\sa-zA-Z._]*)\s?([\w.-]*)", v2)
                        cpe = "cpe:2.3:-:Microsoft:" + v3.group(1).replace(" ", "_") + ":" + v3.group(2)
                        product = v3.group(1).replace(" ", "_")
                        version = v3.group(2)
                    cursor.execute(""" INSERT INTO produit(cpe,vendor, product, version, versionstartincluding, 
                                                            versionendincluding, versionstartexcluding, versionendexcluding, cve_id)
                                                                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                                                                ON CONFLICT (cpe, cve_id) DO NOTHING""",
                                   (cpe, vendor, product, version, versionStartIncluding,
                                    versionEndIncluding,
                                    versionStartExcluding, versionEndExcluding, cve_id))
                    connect.commit()

        description = "Cette vulnérabilité résulte en une " + threat + " et est trouvé dans " + ','.join(products) + "si " + tag + "est installé sur le systeme"

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
    cursor.execute(query, (last, 'Microsoft'))
    connect.commit()
    print("Microsoft update is done")
