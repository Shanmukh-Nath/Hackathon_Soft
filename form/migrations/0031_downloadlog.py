# Generated by Django 3.2.9 on 2023-11-10 10:47

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('form', '0030_participant_participant_id_team_reg_id'),
    ]

    operations = [
        migrations.CreateModel(
            name='DownloadLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('recipient_name', models.CharField(max_length=200)),
                ('recipient_mobile', models.IntegerField(max_length=10)),
                ('recipient_email', models.EmailField(max_length=254)),
                ('download_time', models.DateTimeField(auto_now_add=True)),
                ('initiator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='downloads_initiated', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
