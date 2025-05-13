from django.db import models
from django.contrib.auth.models import User

# Create your models here.

STAKEHOLDER_TYPES = [
    ('CONDUCTOR', 'Trial Conductor'),  # sponsors, CROs, investigators, researchers
    ('OVERSIGHT', 'Oversight Body'),  # ethics committees, regulatory authorities
    ('PARTICIPANT', 'Trial Participant'),
]

class StakeholderProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='stakeholder_profile')
    stakeholder_type = models.CharField(max_length=20, choices=STAKEHOLDER_TYPES)
    organization = models.CharField(max_length=100, blank=True, null=True)
    role = models.CharField(max_length=100, blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.get_stakeholder_type_display()}"

class Protocol(models.Model):
    title = models.CharField(max_length=200)
    version = models.CharField(max_length=20)
    description = models.TextField()
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='protocols')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    hash = models.CharField(max_length=64)  # SHA-256 hash of the protocol content
    previous_version_hash = models.CharField(max_length=64, blank=True, null=True)  # For version tracking
    
    def __str__(self):
        return f"{self.title} - v{self.version}"

class Consent(models.Model):
    participant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='consents')
    protocol = models.ForeignKey(Protocol, on_delete=models.CASCADE, related_name='consents')
    consented_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    consent_hash = models.CharField(max_length=64)  # Hash of consent details for blockchain
    
    def __str__(self):
        return f"Consent: {self.participant.username} - {self.protocol.title}"

