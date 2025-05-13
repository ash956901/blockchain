from django.contrib import admin
from .models import StakeholderProfile, Protocol, Consent

# Register your models here.
admin.site.register(StakeholderProfile)
admin.site.register(Protocol)
admin.site.register(Consent)
