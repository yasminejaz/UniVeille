# UniVeille
Plateforme de veille de vulnérabilités.


Univeille est une plateforme Web de veille de vulnérabilités afin de notifier les entreprises clientes en amont et en continu des nouvelles vulnérabilités de sécurité qui risquent d'affecter leurs actif applicatifs et améliorer leurs processus de gestion de vulnérabilités.



# Fonctionnalités 

## - Collecte de données sur les vulnérabilités
Notre solution collecte les informations sur les vulnérabilités de huits sources differenetes à savoir:

  	1. NVD API,
    2. Redhat Security Data API,
    3. Microsoft Security Response Center API,
    4. IBM X-Force Exchange API,
    5. VMware Security Advisory Feed API,
    6. Google Cloud Flux RSS,
    7. Cisco Flux RSS,
    8. Zero Day Intiative Flux RSS.
   
   /* Schema source */
   
  ### Données sur UNE vulnérabilité:
    . CVE ID,
    . Source,
    . CWE ID,
    . CVSS 2,
    . CVSS 3,
    . Description,
    . Produit(s) affecté(s),
    . Date publication / modification.
   

## - Cartographier les actifs applicatifs 
Notre solution permet aux clients de cartographier leurs actifs applicatifs et ce maniere manuelle ou automatique à l'aide de notre application Desktop qui permet de scanner et collecter les information sur les applications installées sur la machine (Vendor, Product, Version) et les envoyer à la base de données à l'aide d'une REST API.
 /* Capture application */


## - Notification des nouvelles vulnérabilités 
Les entreprises clientes sont notifiées des nouvelles vulnérabilités (a chaque insertion de cette derniere dans la base de données) en fonction de leurs systemes, leurs version et la priorité de l'actif , ainsi que, le niveau de criticité de la vulnérabilité. 




