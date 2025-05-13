from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import StakeholderProfile, Protocol, STAKEHOLDER_TYPES

class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(required=True)
    last_name = forms.CharField(required=True)
    stakeholder_type = forms.ChoiceField(choices=STAKEHOLDER_TYPES, required=True)
    organization = forms.CharField(required=False)
    role = forms.CharField(required=False)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
    
    def save(self, commit=True):
        user = super(UserRegistrationForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']
        
        if commit:
            user.save()
            
            # Create stakeholder profile
            stakeholder_profile = StakeholderProfile(
                user=user,
                stakeholder_type=self.cleaned_data['stakeholder_type'],
                organization=self.cleaned_data['organization'],
                role=self.cleaned_data['role']
            )
            stakeholder_profile.save()
            
        return user

class ProtocolForm(forms.ModelForm):
    class Meta:
        model = Protocol
        fields = ('title', 'version', 'description')
    
    def save(self, user, commit=True):
        protocol = super(ProtocolForm, self).save(commit=False)
        protocol.created_by = user
        
        # Generate hash for the protocol content
        import hashlib
        content = f"{protocol.title}|{protocol.version}|{protocol.description}"
        protocol.hash = hashlib.sha256(content.encode()).hexdigest()
        
        if commit:
            protocol.save()
        
        return protocol
