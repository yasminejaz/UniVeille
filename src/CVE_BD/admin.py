from django.contrib import admin

# Register your models here.
from .models import cve

class CveAdmin(admin.ModelAdmin):
    pass
admin.site.register(cve, CveAdmin)
