# Generated by Django 4.2.5 on 2023-09-30 06:18

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('form', '0018_alter_userprofile_current_session_id'),
    ]

    operations = [
        migrations.AlterField(
            model_name='participant',
            name='email',
            field=models.EmailField(max_length=254, unique=True),
        ),
        migrations.AlterField(
            model_name='participant',
            name='mobile',
            field=models.CharField(max_length=15, unique=True),
        ),
    ]
