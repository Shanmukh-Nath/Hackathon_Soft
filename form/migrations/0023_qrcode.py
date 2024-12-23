# Generated by Django 4.2.5 on 2023-10-05 05:20

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('form', '0022_checkinotp'),
    ]

    operations = [
        migrations.CreateModel(
            name='QRCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('unique_code', models.CharField(max_length=20, unique=True)),
                ('participant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='form.participant')),
            ],
        ),
    ]
