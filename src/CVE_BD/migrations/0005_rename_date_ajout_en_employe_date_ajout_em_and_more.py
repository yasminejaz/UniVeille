# Generated by Django 4.0.3 on 2022-05-26 16:36

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CVE_BD', '0004_remove_entreprise_address_en_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='employe',
            old_name='date_ajout_en',
            new_name='date_ajout_em',
        ),
        migrations.AddField(
            model_name='employe',
            name='valide',
            field=models.BooleanField(null=True),
        ),
    ]
