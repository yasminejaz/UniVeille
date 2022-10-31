# Generated by Django 4.0.3 on 2022-05-31 14:10

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('CVE_BD', '0011_remove_notification_admin_email_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='not_affected_asset',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('cpe', models.TextField(null=True)),
                ('affected', models.BooleanField(null=True)),
                ('cve_id', models.ForeignKey(db_column='cve_id', on_delete=django.db.models.deletion.CASCADE, to='CVE_BD.cve')),
                ('nom_en', models.ForeignKey(db_column='nom_en', on_delete=django.db.models.deletion.CASCADE, to='CVE_BD.entreprise')),
            ],
            options={
                'db_table': 'not_affected_asset',
            },
        ),
        migrations.DeleteModel(
            name='pour_asset',
        ),
    ]