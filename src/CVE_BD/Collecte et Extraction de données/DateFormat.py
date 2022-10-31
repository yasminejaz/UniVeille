import re
from datetime import datetime

def DateFormat(date):
    new = re.sub(".*, ", "", date)
    newnew = re.sub(" [0-9]{2}:[0-9]{2}:[0-9]{2} -.*", "", new)
    newdate = datetime.strptime(newnew, "%d %b %Y").date()
    return newdate
