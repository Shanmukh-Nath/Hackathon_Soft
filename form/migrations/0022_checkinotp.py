# Generated by Django 4.2.5 on 2023-10-02 14:39

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('form', '0021_participant_is_checkedin'),
    ]

    operations = [
        migrations.CreateModel(
            name='CheckInOTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=6)),
                ('sent_time', models.DateTimeField(auto_now_add=True)),
                ('usage_time', models.DateTimeField(blank=True, null=True)),
                ('is_expired', models.BooleanField(default=False)),
                ('participant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='form.participant')),
            ],
        ),
    ]