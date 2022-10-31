import requests
import re


def CPE(sD, eD, cursor, connect):
    url = "https://services.nvd.nist.gov/rest/json/cpes/1.0?apikey=1244f1b5-d882-4d26-a528-38a900427fc0" \
          f"&resultsPerPage=2000&modStartDate={sD}&modEndDate={eD}&addOns=cves"

    response = requests.get(url)
    data = response.json()['result']['cpes']

    for cpe in data:
        for cve in cpe['vulnerabilities']:
            if cve:
                cve_id = cve
                cpe = cpe['cpe23Uri']
                check = re.search(
                    "cpe:2.3:([aoh]):([\\w.@^&/()=\[\]~!$?+#|'%*,><\"\\\-]*):([\\w.@^&/\[\]()=~!?+#|'%*,>$<\"\\\-]*):([\\w.@^&/$\[\]()=~!?+#|'%*,><\"\\\-]*):",
                    cpe["cpe23Uri"])

                vendor = re.sub(" ", "", check.group(1))
                product = re.sub(" ", "", check.group(2))
                version = re.sub(" ", "", check.group(3))

                cursor.execute("""INSERT INTO product(cpe, vendor, product, version, cve_id) 
                                            VALUES (%s,%s,%s,%s,%s)
                                            ON CONFLICT (cpe,cve_id) DO NOTHING
                                        """,
                               (cpe, vendor,product,version,cve_id)
                               )
                connect.commit()
    query = """Update lastupdate SET last_update =%s 
        WHERE source =%s"""
    cursor.execute(query, (eD, 'CPE'))
    connect.commit()
