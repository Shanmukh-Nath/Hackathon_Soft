# Generated by Django 4.2.5 on 2023-09-28 13:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('form', '0014_alter_participant_edited_by'),
    ]

    operations = [
        migrations.AlterField(
            model_name='coordinator',
            name='mobile',
            field=models.IntegerField(blank=True, max_length=15),
        ),
    ]
