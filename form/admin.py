from django.contrib import admin
from . import models

admin.site.register(models.Coordinator)
admin.site.register(models.Participant)
admin.site.register(models.Team)
admin.site.register(models.Domain)

# Register your models here.
