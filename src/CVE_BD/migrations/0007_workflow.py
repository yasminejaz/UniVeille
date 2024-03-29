# Generated by Django 4.0.3 on 2022-05-28 13:22

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('CVE_BD', '0006_notif_date_ajout'),
    ]

    operations = [
        migrations.CreateModel(
            name='workflow',
            fields=[
                ('id_cart', models.AutoField(primary_key=True, serialize=False, unique=True)),
                ('colonne', models.TextField(null=True)),
                ('cve_id', models.ForeignKey(db_column='cve_id', on_delete=django.db.models.deletion.CASCADE, to='CVE_BD.cve')),
                ('id_actif', models.ForeignKey(db_column='id', on_delete=django.db.models.deletion.CASCADE, to='CVE_BD.actifs')),
                ('nom_en', models.ForeignKey(db_column='nom_en', on_delete=django.db.models.deletion.CASCADE, to='CVE_BD.entreprise')),
            ],
            options={
                'db_table': 'workflow',
            },
        ),
    ]
