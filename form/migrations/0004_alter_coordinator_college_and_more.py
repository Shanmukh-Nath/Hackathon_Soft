# Generated by Django 4.2.5 on 2023-09-28 04:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('form', '0003_coordinator_superuser'),
    ]

    operations = [
        migrations.AlterField(
            model_name='coordinator',
            name='college',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AlterField(
            model_name='coordinator',
            name='date_of_birth',
            field=models.DateField(default=''),
        ),
        migrations.AlterField(
            model_name='coordinator',
            name='email',
            field=models.EmailField(default='', max_length=254, unique=True),
        ),
        migrations.AlterField(
            model_name='coordinator',
            name='first_name',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AlterField(
            model_name='coordinator',
            name='last_name',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AlterField(
            model_name='coordinator',
            name='mobile',
            field=models.CharField(default='', max_length=15),
        ),
        migrations.AlterField(
            model_name='coordinator',
            name='state',
            field=models.CharField(default='', max_length=100),
        ),
    ]
