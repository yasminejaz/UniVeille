import re
import requests

from Param import *


def NVD(sD, eD, cursor, connect):
    global cvss2_vector_string, cvss2_access_vector, cvss2_access_complexity, cvss2_authentication, \
        cvss2_confidentiality_impact, cvss2_impact_score, cvss2_obtain_all_priv, cvss2_obtain_user_priv, \
        cvss2_obtain_other_priv, cvss2_user_interaction, cvss3_vector_string, cvss3_attack_vector, \
        cvss3_attack_complexity, cvss3_priv_required, cvss3_user_interaction, cvss3_scope, cvss3_sevirity, \
        cvss3_confidentiality_impact, cvss3_integrity_impact, cvss3_availibility_impact, cvss3_score, \
        cvss3_exploit_score, cvss3_impact_score, cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, \
        cvss2_sevirity, cvss2_exploit_score, tag_exploit, tag_patch, tag_mitigation, tag_vendor_advisory, \
        tag_third_party_advisory, versionStartIncluding, versionEndIncluding, versionStartExcluding, versionEndExcluding

    url = "https://services.nvd.nist.gov/rest/json/cves/1.0?apikey=1244f1b5-d882-4d26-a528-38a900427fc0" \
          f"&resultsPerPage=2000&modStartDate={sD}&modEndDate={eD}"
    response = requests.get(url)
    data = response.json()["result"]['CVE_Items']

    for vuln in data:
        cve_id = vuln["cve"]["CVE_data_meta"]["ID"]
        titre = None
        date_publication = re.sub("T.*", "", vuln["publishedDate"])
        date_modification = re.sub("T.*", "", vuln["lastModifiedDate"])
        source = vuln["cve"]["CVE_data_meta"]["ASSIGNER"]
        description = vuln["cve"]["description"]["description_data"][0]["value"]

        if "baseMetricV2" in vuln["impact"]:
            cvss2_vector_string = vuln["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]
            cvss2_access_vector = vuln["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
            cvss2_access_complexity = vuln["impact"]["baseMetricV2"]["cvssV2"]["accessComplexity"]
            cvss2_authentication = vuln["impact"]["baseMetricV2"]["cvssV2"]["authentication"]
            cvss2_confidentiality_impact = vuln["impact"]["baseMetricV2"]["cvssV2"]["confidentialityImpact"]
            cvss2_integrity_impact = vuln["impact"]["baseMetricV2"]["cvssV2"]["integrityImpact"]
            cvss2_availibility_impact = vuln["impact"]["baseMetricV2"]["cvssV2"]["availabilityImpact"]
            cvss2_score = vuln["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            cvss2_sevirity = vuln["impact"]["baseMetricV2"]["severity"]
            cvss2_exploit_score = vuln["impact"]["baseMetricV2"]["exploitabilityScore"]
            cvss2_impact_score = vuln["impact"]["baseMetricV2"]["impactScore"]
            cvss2_obtain_all_priv = vuln["impact"]["baseMetricV2"]["obtainAllPrivilege"]
            cvss2_obtain_user_priv = vuln["impact"]["baseMetricV2"]["obtainUserPrivilege"]
            cvss2_obtain_other_priv = vuln["impact"]["baseMetricV2"]["obtainOtherPrivilege"]
            if "userInteractionRequired" in vuln["impact"]["baseMetricV2"].keys():
                cvss2_user_interaction = vuln["impact"]["baseMetricV2"]["userInteractionRequired"]

        if "baseMetricV3" in vuln["impact"]:
            cvss3_vector_string = vuln["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]
            cvss3_attack_vector = vuln["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
            cvss3_attack_complexity = vuln["impact"]["baseMetricV3"]["cvssV3"]["attackComplexity"]
            cvss3_priv_required = vuln["impact"]["baseMetricV3"]["cvssV3"]["privilegesRequired"]
            cvss3_user_interaction = vuln["impact"]["baseMetricV3"]["cvssV3"]["userInteraction"]
            cvss3_scope = vuln["impact"]["baseMetricV3"]["cvssV3"]["scope"]
            if "baseSeverity" in vuln["impact"]["baseMetricV3"]["cvssV3"]:
                cvss3_sevirity = vuln["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
            cvss3_confidentiality_impact = vuln["impact"]["baseMetricV3"]["cvssV3"]["confidentialityImpact"]
            cvss3_integrity_impact = vuln["impact"]["baseMetricV3"]["cvssV3"]["integrityImpact"]
            cvss3_availibility_impact = vuln["impact"]["baseMetricV3"]["cvssV3"]["availabilityImpact"]
            cvss3_score = vuln["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            cvss3_exploit_score = vuln["impact"]["baseMetricV3"]["exploitabilityScore"]
            cvss3_impact_score = vuln["impact"]["baseMetricV3"]["impactScore"]
        cursor.execute("""INSERT INTO cve (cve_id,titre,date_publication,date_modification,source,description,
                                       cvss2_vector_string,cvss2_access_vector,cvss2_access_complexity,cvss2_authentication,cvss2_confidentiality_impact,\
                                       cvss2_integrity_impact,cvss2_availibility_impact,cvss2_score,cvss2_sevirity,cvss2_exploit_score,\
                                       cvss2_impact_score,cvss2_obtain_all_priv,cvss2_obtain_user_priv,cvss2_obtain_other_priv,\
                                       cvss2_user_interaction,cvss3_vector_string,cvss3_attack_vector,cvss3_attack_complexity,cvss3_priv_required,\
                                       cvss3_user_interaction,cvss3_scope,cvss3_sevirity, cvss3_confidentiality_impact,
                                       cvss3_integrity_impact,cvss3_availibility_impact,cvss3_score,cvss3_exploit_score,cvss3_impact_score)
                                       VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                    ON Conflict (cve_id) DO Update SET (titre,date_publication,date_modification,source,
                                    description,cvss2_vector_string,cvss2_access_vector,cvss2_access_complexity,cvss2_authentication,
                                    cvss2_confidentiality_impact,cvss2_integrity_impact,cvss2_availibility_impact,cvss2_score,
                                    cvss2_sevirity,cvss2_exploit_score,cvss2_impact_score,cvss2_obtain_all_priv,cvss2_obtain_user_priv,
                                    cvss2_obtain_other_priv,cvss2_user_interaction,cvss3_vector_string,cvss3_attack_vector,
                                    cvss3_attack_complexity,cvss3_priv_required,cvss3_user_interaction,cvss3_scope,cvss3_sevirity,
                                    cvss3_confidentiality_impact,cvss3_integrity_impact,cvss3_availibility_impact,cvss3_score,
                                    cvss3_exploit_score,cvss3_impact_score)=(EXCLUDED.titre,EXCLUDED.date_publication,
                                    EXCLUDED.date_modification,EXCLUDED.source,EXCLUDED.description,EXCLUDED.cvss2_vector_string,
                                    EXCLUDED.cvss2_access_vector,EXCLUDED.cvss2_access_complexity,EXCLUDED.cvss2_authentication,
                                    EXCLUDED.cvss2_confidentiality_impact,EXCLUDED.cvss2_integrity_impact,
                                    EXCLUDED.cvss2_availibility_impact, EXCLUDED.cvss2_score,EXCLUDED.cvss2_sevirity,
                                    EXCLUDED.cvss2_exploit_score,EXCLUDED.cvss2_impact_score,EXCLUDED.cvss2_obtain_all_priv,
                                    EXCLUDED.cvss2_obtain_user_priv,EXCLUDED.cvss2_obtain_other_priv,
                                    EXCLUDED.cvss2_user_interaction,EXCLUDED.cvss3_vector_string,EXCLUDED.cvss3_attack_vector,
                                    EXCLUDED.cvss3_attack_complexity,EXCLUDED. cvss3_priv_required,
                                    EXCLUDED.cvss3_user_interaction,EXCLUDED.cvss3_scope,EXCLUDED.cvss3_sevirity,
                                    EXCLUDED.cvss3_confidentiality_impact,EXCLUDED.cvss3_integrity_impact,
                                    EXCLUDED.cvss3_availibility_impact,EXCLUDED.cvss3_score,EXCLUDED.cvss3_exploit_score,
                                    EXCLUDED.cvss3_impact_score)
                                       """,
                       (cve_id, titre, date_publication, date_modification, source, description,
                        cvss2_vector_string, cvss2_access_vector, cvss2_access_complexity, cvss2_authentication,
                        cvss2_confidentiality_impact,
                        cvss2_integrity_impact, cvss2_availibility_impact, cvss2_score, cvss2_sevirity,
                        cvss2_exploit_score,
                        cvss2_impact_score, cvss2_obtain_all_priv, cvss2_obtain_user_priv, cvss2_obtain_other_priv,
                        cvss2_user_interaction, cvss3_vector_string, cvss3_attack_vector, cvss3_attack_complexity,
                        cvss3_priv_required,
                        cvss3_user_interaction, cvss3_scope, cvss3_sevirity, cvss3_confidentiality_impact,
                        cvss3_integrity_impact, cvss3_availibility_impact, cvss3_score, cvss3_exploit_score,
                        cvss3_impact_score)
                       )
        connect.commit()

        for ref in vuln["cve"]["references"]["reference_data"]:
            tags = ref["tags"]
            if len(tags) != 0:
                if "Broken Link" not in tags:
                    for tag in tags:
                        if tag == "Vendor Advisory":
                            tag_vendor_advisory = 1

                        if tag == "Third Party Advisory":
                            tag_third_party_advisory = 1

                        if tag == "Mitigation":
                            tag_mitigation = 1

                        if tag == "Patch":
                            tag_patch = 1

                        if tag == "Exploit":
                            tag_exploit = 1
            url = ref["url"]
            cursor.execute(""" INSERT INTO reference(cve_id,url,tag_exploit,tag_patch,tag_mitigation,
                    tag_third_party_advisory,tag_vendor_advisory) VALUES (%s,%s,%s,%s,%s,%s,%s)
                        ON CONFLICT (cve_id,url) DO UPDATE SET (tag_exploit,tag_patch,tag_mitigation,
                    tag_third_party_advisory,tag_vendor_advisory) = (EXCLUDED.tag_exploit, EXCLUDED.tag_patch, 
                    EXCLUDED.tag_mitigation, EXCLUDED.tag_third_party_advisory, EXCLUDED.tag_vendor_advisory)
                                    """,
                           (cve_id, url, tag_exploit, tag_patch, tag_mitigation,
                            tag_third_party_advisory, tag_vendor_advisory)
                           )
            connect.commit()

        for cwe in vuln["cve"]["problemtype"]["problemtype_data"][0]["description"]:
            if cwe["value"] != "NVD-CWE-Other" and cwe["value"] != "NVD-CWE-noinfo":
                cursor.execute("""INSERT INTO cve_cwe(cve_id, cwe_id) values(%s,%s)
                                        ON CONFLICT (cve_id,cwe_id) DO NOTHING
                                         """,
                               (cve_id, cwe["value"])
                               )
                connect.commit()

        for node in vuln["configurations"]["nodes"]:
            if node["children"]:
                for child in node["children"]:
                    for cpe in child["cpe_match"]:
                        cpe_name = cpe["cpe23Uri"]
                        check = re.search(
                            "cpe:2.3:[aoh]:([\\w.@^&/$()=~!?+#|\[\]'%*,><\"\\\-]*):([\\w.@^&/()$\[\]=~!?+#|'%*,><\"\\\-]*):([\\w.@^&$/\[\]()=~!?+#|'%*,><\"\\\-]*):",
                            cpe["cpe23Uri"])

                        vendor = re.sub(" ", "", check.group(1))
                        product = re.sub(" ", "", check.group(2))
                        version = re.sub(" ", "", check.group(3))

                        if "versionStartIncluding" in cpe:
                            versionStartIncluding = cpe["versionStartIncluding"]
                        if "versionEndIncluding" in cpe:
                            versionEndIncluding = cpe["versionEndIncluding"]
                        if "versionStratExcluding" in cpe:
                            versionStartExcluding = cpe["versionStratExcluding"]
                        if "versionEndExcluding" in cpe:
                            versionEndExcluding = cpe["versionEndExcluding"]
                        cursor.execute(""" INSERT INTO produit(cpe, vendor, product, version, versionstartincluding, 
                                        versionendincluding, versionstartexcluding, versionendexcluding, cve_id)
                                                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                                                            ON CONFLICT (cpe, cve_id) DO NOTHING""",
                                       (cpe_name, vendor, product, version, versionStartIncluding,
                                        versionEndIncluding, versionStartExcluding, versionEndExcluding, cve_id))
                        connect.commit()

            for cpe in node["cpe_match"]:
                cpe_name = cpe["cpe23Uri"]
                check = re.search(
                    "cpe:2.3:([aoh]):([\\w.@^&/()=\[\]~!$?+#|'%*,><\"\\\-]*):([\\w.@^&/\[\]()=~!?+#|'%*,>$<\"\\\-]*):([\\w.@^&/$\[\]()=~!?+#|'%*,><\"\\\-]*):",
                    cpe["cpe23Uri"])

                vendor = re.sub(" ","",check.group(1))
                product = re.sub(" ","",check.group(2))
                version = re.sub(" ","",check.group(3))
                if "versionStartIncluding" in cpe:
                    versionStartIncluding = cpe["versionStartIncluding"]
                if "versionEndIncluding" in cpe:
                    versionEndIncluding = cpe["versionEndIncluding"]
                if "versionStratExcluding" in cpe:
                    versionStartExcluding = cpe["versionStratExcluding"]
                if "versionEndExcluding" in cpe:
                    versionEndExcluding = cpe["versionEndExcluding"]

                cursor.execute(""" INSERT INTO produit(cpe,vendor, product, version, versionstartincluding, 
                versionendincluding, versionstartexcluding, versionendexcluding, cve_id)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                                    ON CONFLICT (cpe, cve_id) DO NOTHING""",
                               (cpe_name, vendor, product, version, versionStartIncluding, versionEndIncluding,
                                versionStartExcluding, versionEndExcluding, cve_id))
                connect.commit()
    query = """Update lastupdate SET last_update =%s 
    WHERE source =%s"""
    cursor.execute(query, (eD, 'NVD'))
    connect.commit()

    print("NVD Update: "+eD+"  is done!")
