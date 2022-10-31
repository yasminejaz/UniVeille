import feedparser
import requests
import re
from Param import *
from bs4 import BeautifulSoup
from CVSS3 import cvss3_att_value
from DateFormat import *


def ZDI(cursor, connect):
    feed_url = "https://www.zerodayinitiative.com/rss/published/"

    NewsFeed = feedparser.parse(feed_url)

    for info in NewsFeed.entries:
        url = f"https://www.zerodayinitiative.com/advisories/{info.id}/"
        page = requests.get(url)
        soup = BeautifulSoup(page.text, 'lxml')
        for content in soup.findAll('table'):
            cve_id = content.select('tr > td')[1].text.replace('\n', '')
            titre = info.title
            date_publication = DateFormat(info.published)
            description = content.select('tr > td')[9].text.replace('\n', '')
            cvss3_score = re.sub(',.*', '', content.select('tr > td')[3].text).replace(' ', '').replace('\n', '')
            cvss3_vector = re.sub('.*,', '', content.select('tr > td')[3].text).replace('\n', '').replace(' ','').replace(
                '(', '').replace(')', '')
            cvss3_attack_vector, cvss3_attack_cpmplexity, cvss3_priv_required, \
            cvss3_user_interaction, cvss3_scope, cvss3_confidentiality_impact, \
            cvss3_integrity_impact, cvss3_availibility_impact = cvss3_att_value(cvss3_vector)

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
    cursor.execute(query, (last, 'ZDI'))
    connect.commit()
    print("ZDI update is done")

    """
            affected_vendor'] = content.select('tr > td')[5].text.replace('\n', '')
            affected_product'] = content.select('tr > td')[7].text.replace('\n', '').replace(' ', '')
    """