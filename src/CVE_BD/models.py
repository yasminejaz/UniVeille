from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save


class cve(models.Model):
    cve_id = models.TextField(primary_key=True, unique=True)
    titre = models.TextField(null=True)
    date_publication = models.TextField(null=True)
    date_modification = models.TextField(null=True)
    source = models.TextField(null=True)
    description = models.TextField(null=True)
    cvss2_vector_string = models.TextField(null=True)
    cvss2_access_vector = models.TextField(null=True)
    cvss2_access_complexity = models.TextField(null=True)
    cvss2_authentication = models.TextField(null=True)
    cvss2_confidentiality_impact = models.TextField(null=True)
    cvss2_integrity_impact = models.TextField(null=True)
    cvss2_availibility_impact = models.TextField(null=True)
    cvss2_score = models.IntegerField(null=True)
    cvss2_sevirity = models.TextField(null=True)
    cvss2_exploit_score = models.IntegerField(null=True)
    cvss2_impact_score= models.IntegerField(null=True)
    cvss2_obtain_all_priv = models.BooleanField(null=True)
    cvss2_obtain_user_priv = models.BooleanField(null=True)
    cvss2_obtain_other_priv= models.BooleanField(null=True)
    cvss2_user_interaction = models.BooleanField(null=True)
    cvss3_vector_string = models.TextField(null=True)
    cvss3_attack_vector = models.TextField(null=True)
    cvss3_attack_complexity = models.TextField(null=True)
    cvss3_priv_required = models.TextField(null=True)
    cvss3_user_interaction = models.TextField(null=True)
    cvss3_scope = models.TextField(null=True)
    cvss3_sevirity = models.TextField(null=True)
    cvss3_confidentiality_impact = models.TextField(null=True)
    cvss3_integrity_impact = models.TextField(null=True)
    cvss3_availibility_impact = models.TextField(null=True)
    cvss3_score = models.IntegerField(null=True)
    cvss3_exploit_score = models.IntegerField(null=True)
    cvss3_impact_score = models.IntegerField(null=True)
    class Meta:
        db_table = 'cve'



class reference(models.Model):
    cve_id = models.ForeignKey(cve, on_delete=models.CASCADE, db_column='cve_id')
    reference = models.TextField(null=True)
    tag_exploit =models.IntegerField(null=True)
    tag_patch= models.IntegerField(null=True)
    tag_mitigation= models.IntegerField(null=True)
    tag_third_party_advisory = models.IntegerField(null=True)
    tag_vendor_advisory =models.IntegerField(null=True)


    class Meta:
        db_table ='reference'
        constraints = [
            models.UniqueConstraint(fields=['cve_id', 'reference'], name ='cve_ref')
        ]



class product(models.Model):
    cpe = models.TextField(null=True)
    cpe_minimal = models.TextField(null=True)
    vendor = models.TextField(null=True)
    product = models.TextField(null=True)
    version = models.TextField(null=True)
    cve_id = models.ForeignKey(cve, on_delete=models.CASCADE,db_column='cve_id')

    class Meta:
        db_table='product'
        constraints = [
            models.UniqueConstraint(fields=['cpe', 'cve_id'], name='cpecve')
        ]
        indexes = [
            models.Index(fields=['product', 'vendor', 'version'])
        ]


class cwe(models.Model):
    cwe_id = models.TextField(primary_key=True, unique=True)
    title = models.TextField(null=True)
    class Meta:
        db_table = 'cwe'

    def __str__(self):
        return self.cwe_id

class cve_cwe(models.Model):
    cve_id = models.ForeignKey(cve, on_delete=models.DO_NOTHING, db_column='cve_id')
    cwe_id = models.ForeignKey(cwe, on_delete=models.CASCADE, db_column='cwe_id')
    class Meta:
        db_table = "cve_cwe"
        constraints = [
            models.UniqueConstraint(fields=['cve_id','cwe_id'],name='cvecwe_unique')
        ]


class entreprise(models.Model):
    nom_en = models.TextField(primary_key=True, unique=True)
    secteur_activité_en = models.TextField(null=True)
    url_en = models.TextField(null=True)
    date_ajout_en = models.TextField(null=True)

    class Meta:
        db_table = 'entreprise'

class employe(models.Model):
    email = models.TextField(primary_key=True, unique=True)
    nom = models.TextField(null=True)
    prenom = models.TextField(null=True)
    num_tel= models.TextField(null=True)
    job_title=  models.TextField(null=True)
    date_ajout_em = models.TextField(null=True)
    date_modif_statut = models.TextField(null=True)
    valide  = models.BooleanField(null=True)
    nom_entreprise =models.ForeignKey(entreprise, on_delete=models.CASCADE,db_column='nom_en')
    user_id=  models.ForeignKey(User, on_delete=models.CASCADE,db_column='id')

    class Meta:
        db_table = 'employe'

    def  __str__(self):
        return  str(self.user_id)
def create_employe(sender,instance,created, **kwargs):
    if created:
        data =User.objects.filter(username = instance )
        test = User.objects.get(username=instance)
        notification_admin.objects.create( user_id_id=data[0].id,checked=False)
post_save.connect(create_employe,sender=User)




class actifs(models.Model):
    nom_actif =models.TextField(null=True)
    nom_vendor=models.TextField(null=True)
    version_actif=models.TextField(null=True)
    importance_actif = models.TextField(null=True)
    date_ajout_actif =models.TextField(null=True)
    new_cpe_actif = models.TextField(null=True)
    nom_en =models.ForeignKey(entreprise, on_delete=models.CASCADE,db_column='nom_en')

    class Meta:
        db_table = 'actifs'

    # Contrainte
    constraints = [
        models.UniqueConstraint(fields=["new_cpe_actif", "nom_en"], name='cpe_unique')
    ]



class pour_asset(models.Model):
    cpe = models.TextField(null=True)
    affected= models.BooleanField(null=True)
    nom_en = models.ForeignKey(entreprise, on_delete=models.CASCADE, db_column='nom_en',default="lesi")
    cve_id = models.ForeignKey(cve, on_delete=models.CASCADE,db_column='cve_id')

    class Meta:
        db_table = 'pour_asset'


class actif_products(models.Model):
    id_table= models.AutoField(primary_key=True, unique=True)
    id_actif_client = models.ForeignKey(actifs, on_delete=models.CASCADE)
    cve_id = models.ForeignKey(cve, on_delete=models.CASCADE, db_column='cve_id')
    cpe= models.TextField(null=True)

    class Meta:
        db_table = 'actif_products'


class notif(models.Model):
    id_notif =models.AutoField(primary_key=True, unique=True)
    nom_actif = models.TextField(null=True)
    date_ajout = models.TextField(null=True)
    nom_en = models.ForeignKey(entreprise, on_delete=models.CASCADE, db_column='nom_en')
    cve_id = models.ForeignKey(cve, on_delete=models.CASCADE, db_column='cve_id')
    id_ajout = models.ForeignKey(actifs, on_delete=models.CASCADE, db_column='id')
    checked=models.BooleanField(null=True)

    class Meta:
        db_table = 'notification'


class notification_admin(models.Model):
    id_notif_admin =models.AutoField(primary_key=True, unique=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, db_column='id')
    checked=models.BooleanField(null=True)

    class Meta:
        db_table = 'notification_admin'


class workflow(models.Model):
    id_cart =models.AutoField(primary_key=True, unique=True)
    nom_en = models.ForeignKey(entreprise, on_delete=models.CASCADE, db_column='nom_en')
    id_actif = models.ForeignKey(actifs, on_delete=models.CASCADE, db_column='id')
    cve_id = models.ForeignKey(cve, on_delete=models.CASCADE, db_column='cve_id')
    colonne = models.IntegerField(null=True)
    date_ajout = models.TextField(null=True)

    class Meta:
        db_table = 'workflow'