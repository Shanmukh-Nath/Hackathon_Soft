# Generated by Django 4.2.5 on 2023-11-07 11:40

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("form", "0029_participanttype_alter_participant_participant_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="participant",
            name="participant_id",
            field=models.CharField(blank=True, max_length=12, null=True, unique=True),
        ),
        migrations.AddField(
            model_name="team",
            name="reg_id",
            field=models.CharField(default=0, max_length=12),
        ),
    ]
