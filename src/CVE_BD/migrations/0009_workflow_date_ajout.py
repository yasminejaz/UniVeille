# Generated by Django 4.0.3 on 2022-05-28 13:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('CVE_BD', '0008_alter_workflow_colonne'),
    ]

    operations = [
        migrations.AddField(
            model_name='workflow',
            name='date_ajout',
            field=models.TextField(null=True),
        ),
    ]
