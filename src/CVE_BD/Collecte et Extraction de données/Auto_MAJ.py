import pandas

from NVD import *
from Redhat import *
from IBM import *
from Microsoft import *
from GoogleCloud import *
from VMware import *
from Cisco import *
from ZDI import *
from CPE import *
from apscheduler.schedulers.background import BackgroundScheduler
from time import sleep
from datetime import datetime


import psycopg2
connect = psycopg2.connect(
    host="localhost",
    port='5432',
    dbname="CVE",
    user="postgres",
    password="P@ssword"
)
cursor = connect.cursor()

s = BackgroundScheduler()


cursor.execute("Select last_update from lastupdate where source = 'NVD'")
startnvd = cursor.fetchone()[0]
endnvd = re.sub('\..*', ':000', datetime.now().isoformat())+" UTC%2B01:00"

s.add_job(NVD, 'interval', args=[startnvd, endnvd, cursor, connect], hours=2)

cursor.execute("Select last_update from lastupdate where source = 'CPE'")
startcpe = cursor.fetchone()[0]
endcpe = re.sub('\..*', ':000', datetime.now().isoformat())+" UTC%2B01:00"

s.add_job(CPE, 'interval', args=[startcpe, endcpe, cursor, connect], hours=2)

cursor.execute("Select last_update from lastupdate where source = 'IBM'")
startibm = cursor.fetchone()[0]

s.add_job(IBM, 'interval', args=[startibm, cursor, connect], hours=24)


cursor.execute("Select last_update from lastupdate where source = 'Redhat'")
startrh = cursor.fetchone()[0]

s.add_job(Redhat, 'interval', args=[startrh, cursor, connect], hours=24)

s.add_job(MSC, 'interval', args=[cursor, connect], hours=24)

s.add_job(GoogleCloud, 'interval', args=[cursor, connect], hours=24)

s.add_job(VMware, 'interval', args=[cursor, connect], hours=24)

s.add_job(Cisco, 'interval', args=[cursor, connect], hours=24)

s.add_job(ZDI, 'interval', args=[cursor, connect], hours=24)

s.start()


while True:
    sleep(1)


