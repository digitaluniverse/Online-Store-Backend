# Generated by Django 3.1.7 on 2021-05-26 04:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0006_auto_20210526_0417'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='reset_authorized',
            field=models.BooleanField(default=False),
        ),
    ]
