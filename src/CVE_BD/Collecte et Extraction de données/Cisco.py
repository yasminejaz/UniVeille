import re
from datetime import datetime

from Param import *
import feedparser
import requests
from bs4 import BeautifulSoup
from CVSS3 import cvss3_att_value, cvss3severity


def Cisco(cursor, connect):

    feed_url = "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
    NewsFeed = feedparser.parse(feed_url)

    for info in NewsFeed.entries:
        titre = info.title
        date_publication = re.sub(" .*", "", info.published)

        page = requests.get(info.id)
        soup = BeautifulSoup(page.text, 'lxml')
        cvss3_score = re.sub('\sCVSS.*', '', soup.find('input', {'id': 'hdncvssvector'})['value']).replace(
            'Base ',
            '')
        cvss3_severity = cvss3severity(cvss3_score)
        cvss3_vector= re.sub('.*CVSS:3.1/', '', soup.find('input', {'id': 'hdncvssvector'})['value'])
        cvss3_attack_vector, cvss3_attack_cpmplexity, cvss3_priv_required, \
        cvss3_user_interaction, cvss3_scope, cvss3_confidentiality_impact, \
        cvss3_integrity_impact, cvss3_availibility_impact= cvss3_att_value(cvss3_vector)

        content = soup.find('div', {'class': 'CVEList'})  # GET ALL CVE ID
        if "More..." in [text for text in content.stripped_strings]:
            content = soup.find('span', {'id': 'fullcvecontent_content'})
            cves=content.text.split(',')
        else :
            cves = [text for text in content.stripped_strings]

        content = soup.find('div', {'class': 'CWEList'})  # GET ALL CWE ID
        cwes = [text for text in content.stripped_strings]

        content = soup.find('div', {'id': 'summaryfield'})
        description = '\n'.join([text for text in content.stripped_strings])

        for cve_id in cves:

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

            for cwe_id in cwes:
                cursor.execute("""INSERT INTO cve_cwe (cve_id, cwe_id)
                                                        VALUES (%s, %s) ON CONFLICT (cve_id,cwe_id) DO NOTHING """,
                               (cve_id, cwe_id)
                               )
                connect.commit()

    last = datetime.now().strftime("%Y-%m-%d")
    query = """Update lastupdate SET last_update =%s                         
    WHERE source =%s"""
    cursor.execute(query, (last, 'Cisco'))
    connect.commit()
    print("Cisco update is done")
    '''
        content = soup.find('div', {'id': 'vulnerableproducts'})
        print(content.get_text('\n', strip=True))
    '''