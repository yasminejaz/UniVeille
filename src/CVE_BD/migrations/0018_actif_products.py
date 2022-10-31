# Generated by Django 4.0.3 on 2022-06-01 09:14

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('CVE_BD', '0017_delete_actif_products'),
    ]

    operations = [
        migrations.CreateModel(
            name='actif_products',
            fields=[
                ('id_table', models.AutoField(primary_key=True, serialize=False, unique=True)),
                ('cpe', models.TextField(null=True)),
                ('cve_id', models.ForeignKey(db_column='cve_id', on_delete=django.db.models.deletion.CASCADE, to='CVE_BD.cve')),
                ('id_actif_client', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='CVE_BD.actifs')),
            ],
            options={
                'db_table': 'actif_products',
            },
        ),
    ]
