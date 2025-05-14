from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Count
from django.utils import timezone
import json
from django.contrib.auth import login as auth_login, logout as auth_logout

from .models import StakeholderProfile, Protocol, Consent
from .views import get_last_block, create_new_block, save_block_to_file, log_audit_event
from django.contrib.auth.forms import AuthenticationForm

from .forms import UserRegistrationForm, ProtocolForm
from .models import StakeholderProfile, Protocol, Consent, STAKEHOLDER_TYPES
from .views import verify_blockchain, get_blockchain_data, log_audit_event

def custom_login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_login(request, user)
            
            # Redirect based on stakeholder type
            try:
                profile = user.stakeholder_profile
                if profile.stakeholder_type == 'CONDUCTOR':
                    return redirect('conductor_dashboard')
                elif profile.stakeholder_type == 'OVERSIGHT':
                    return redirect('oversight_dashboard')
                elif profile.stakeholder_type == 'PARTICIPANT':
                    return redirect('participant_dashboard')
            except StakeholderProfile.DoesNotExist:
                pass
            
            # Default redirect if no profile or unknown type
            return redirect('index')
    else:
        form = AuthenticationForm()
    
    return render(request, 'CTPortal/login.html', {'form': form})

def custom_logout(request):
    # Log the logout event
    if request.user.is_authenticated:
        log_audit_event("USER_LOGOUT", f"User logged out: {request.user.username}", "Logout successful")
    
    # Perform the logout
    auth_logout(request)
    
    # Redirect to login page
    messages.success(request, "You have been successfully logged out.")
    return redirect('login')

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            stakeholder_type = form.cleaned_data.get('stakeholder_type')
            log_audit_event("USER_REGISTRATION", f"New user registered: {user.username}", f"Stakeholder type: {stakeholder_type}")
            messages.success(request, f'Account created successfully. You can now log in.')
            return redirect('login')
    else:
        form = UserRegistrationForm()
    return render(request, 'CTPortal/register.html', {'form': form})

@login_required
def conductor_dashboard(request):
    # Get user's stakeholder profile
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type != 'CONDUCTOR':
            messages.error(request, "You don't have permission to access this dashboard.")
            if profile.stakeholder_type == 'OVERSIGHT':
                return redirect('oversight_dashboard')
            elif profile.stakeholder_type == 'PARTICIPANT':
                return redirect('participant_dashboard')
            return redirect('index')
    except StakeholderProfile.DoesNotExist:
        messages.error(request, "You don't have a stakeholder profile.")
        return redirect('index')
    
    # Get protocols created by this user
    protocols = Protocol.objects.filter(created_by=request.user).order_by('-updated_at')
    
    # Get counts for dashboard
    participant_count = User.objects.filter(stakeholder_profile__stakeholder_type='PARTICIPANT').count()
    protocol_count = Protocol.objects.count()
    consent_count = Consent.objects.count()
    
    # Get blockchain status
    chain_status = "Valid" if verify_blockchain() else "Invalid"
    
    # Get blockchain data for visualization
    blockchain_data = []
    blockchain_df = get_blockchain_data()
    if not blockchain_df.empty:
        for index, row in blockchain_df.iterrows():
            block_data = {
                'index': row.get('BlockIndex', 'N/A'),
                'hash': row.get('BlockHash', 'N/A'),
                'previous_hash': row.get('PreviousHash', 'N/A'),
                'timestamp': row.get('Timestamp', 'N/A'),
                'data_preview': f"Participant #{row.get('ParticipantEnrollmentNumber', 'N/A')}",
                'valid': True  # We'll assume valid for now, could implement per-block validation
            }
            blockchain_data.append(block_data)
    
    context = {
        'user': request.user,
        'protocols': protocols,
        'participant_count': participant_count,
        'protocol_count': protocol_count,
        'consent_count': consent_count,
        'chain_status': chain_status,
        'blockchain_data': blockchain_data
    }
    
    return render(request, 'CTPortal/conductor_dashboard.html', context)

@login_required
def oversight_dashboard(request):
    # Get user's stakeholder profile
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type != 'OVERSIGHT':
            messages.error(request, "You don't have permission to access this dashboard.")
            if profile.stakeholder_type == 'CONDUCTOR':
                return redirect('conductor_dashboard')
            elif profile.stakeholder_type == 'PARTICIPANT':
                return redirect('participant_dashboard')
            return redirect('index')
    except StakeholderProfile.DoesNotExist:
        messages.error(request, "You don't have a stakeholder profile.")
        return redirect('index')
    
    # Get all protocols for oversight
    protocols = Protocol.objects.all().order_by('-updated_at')
    
    # Get counts for dashboard
    participant_count = User.objects.filter(stakeholder_profile__stakeholder_type='PARTICIPANT').count()
    protocol_count = Protocol.objects.count()
    consent_count = Consent.objects.count()
    
    # Get blockchain status
    chain_status = "Valid" if verify_blockchain() else "Invalid"
    
    context = {
        'user': request.user,
        'protocols': protocols,
        'participant_count': participant_count,
        'protocol_count': protocol_count,
        'consent_count': consent_count,
        'chain_status': chain_status
    }
    
    return render(request, 'CTPortal/oversight_dashboard.html', context)

@login_required
def participant_dashboard(request):
    # Get user's stakeholder profile
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type != 'PARTICIPANT':
            messages.error(request, "You don't have permission to access this dashboard.")
            if profile.stakeholder_type == 'CONDUCTOR':
                return redirect('conductor_dashboard')
            elif profile.stakeholder_type == 'OVERSIGHT':
                return redirect('oversight_dashboard')
            return redirect('index')
    except StakeholderProfile.DoesNotExist:
        messages.error(request, "You don't have a stakeholder profile.")
        return redirect('index')
    
    # Get consents for this participant
    consented_protocols = Consent.objects.filter(participant=request.user, is_active=True).select_related('protocol')
    
    # Get available protocols that this participant hasn't consented to
    consented_protocol_ids = consented_protocols.values_list('protocol_id', flat=True)
    available_protocols = Protocol.objects.exclude(id__in=consented_protocol_ids)
    
    context = {
        'user': request.user,
        'consented_protocols': consented_protocols,
        'available_protocols': available_protocols,
        'consented_protocols_count': consented_protocols.count(),
        'available_protocols_count': available_protocols.count(),
        'active_trials_count': consented_protocols.count()  # All consented protocols are considered active
    }
    
    return render(request, 'CTPortal/participant_dashboard.html', context)

@login_required
def protocol_list(request):
    # Get user's stakeholder profile
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type == 'CONDUCTOR':
            # Trial conductors see only their protocols
            protocols = Protocol.objects.filter(created_by=request.user).order_by('-updated_at')
        elif profile.stakeholder_type == 'OVERSIGHT':
            # Oversight bodies see all protocols
            protocols = Protocol.objects.all().order_by('-updated_at')
        elif profile.stakeholder_type == 'PARTICIPANT':
            # Participants see protocols they've consented to
            protocols = Protocol.objects.filter(consents__participant=request.user).order_by('-updated_at')
        else:
            protocols = []
    except StakeholderProfile.DoesNotExist:
        protocols = []
    
    context = {
        'protocols': protocols
    }
    
    return render(request, 'CTPortal/protocol_list.html', context)

# Function to record blockchain events for protocols and consents
def record_blockchain_event(event_type, data_dict):
    """Record protocol and consent events in the blockchain"""
    try:
        # Get the last block
        last_block = get_last_block()
        
        # Create a new block with the event data
        new_block = create_new_block(last_block, data_dict)
        
        # Save the block to the blockchain
        save_block_to_file(new_block)
        
        # Log the event
        log_audit_event(f"BLOCKCHAIN_{event_type}_RECORDED", f"{event_type} recorded in blockchain", f"Block #{new_block.index}")
        
        return True
    except Exception as e:
        print(f"Error recording blockchain event: {e}")
        log_audit_event(f"BLOCKCHAIN_{event_type}_FAILED", f"Failed to record {event_type} in blockchain", f"Error: {str(e)}")
        return False

def protocol_create(request):
    # Only trial conductors can create protocols
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type != 'CONDUCTOR':
            messages.error(request, "Only trial conductors can create protocols.")
            return redirect('protocol_list')
    except StakeholderProfile.DoesNotExist:
        messages.error(request, "You don't have a stakeholder profile.")
        return redirect('index')
    
    if request.method == 'POST':
        form = ProtocolForm(request.POST)
        if form.is_valid():
            protocol = form.save(user=request.user)
            
            # Record protocol creation in blockchain
            protocol_data = {
                'EventType': 'PROTOCOL_CREATED',
                'ProtocolID': protocol.id,
                'Title': protocol.title,
                'Version': protocol.version,
                'CreatedBy': protocol.created_by.username,
                'CreatedAt': protocol.created_at.isoformat()
            }
            record_blockchain_event('PROTOCOL_CREATED', protocol_data)
            
            log_audit_event("PROTOCOL_CREATED", f"Protocol created: {protocol.title}", f"By: {request.user.username}")
            messages.success(request, f'Protocol "{protocol.title}" created successfully.')
            return redirect('protocol_list')
    else:
        form = ProtocolForm()
    
    return render(request, 'CTPortal/protocol_form.html', {'form': form})

@login_required
def protocol_detail(request, protocol_id):
    try:
        protocol = Protocol.objects.get(pk=protocol_id)
    except Protocol.DoesNotExist:
        messages.error(request, "Protocol not found.")
        return redirect('protocol_list')
    
    # Get consent status for this protocol if user is a participant
    user_consent = None
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type == 'PARTICIPANT':
            try:
                user_consent = Consent.objects.get(participant=request.user, protocol=protocol, is_active=True)
            except Consent.DoesNotExist:
                # Check if there's an inactive consent
                try:
                    inactive_consent = Consent.objects.get(participant=request.user, protocol=protocol, is_active=False)
                    # If there is an inactive consent, we still keep user_consent as None
                    # but we'll add a message to inform the user
                    messages.info(request, "You previously revoked your consent for this protocol.")
                except Consent.DoesNotExist:
                    pass
    except StakeholderProfile.DoesNotExist:
        pass
    
    # Get participant count for this protocol
    participant_count = Consent.objects.filter(protocol=protocol, is_active=True).count()
    
    # Get all consents for conductors and oversight bodies
    consents = []
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type in ['CONDUCTOR', 'OVERSIGHT']:
            consents = Consent.objects.filter(protocol=protocol).select_related('participant')
    except StakeholderProfile.DoesNotExist:
        pass
    
    # Get previous versions of this protocol
    previous_versions = []
    if protocol.previous_version_hash:
        previous_versions = Protocol.objects.filter(hash=protocol.previous_version_hash)
    
    context = {
        'protocol': protocol,
        'user_consent': user_consent,
        'participant_count': participant_count,
        'consents': consents,
        'previous_versions': previous_versions
    }
    
    return render(request, 'CTPortal/protocol_detail.html', context)

@login_required
def protocol_update(request, protocol_id):
    try:
        protocol = Protocol.objects.get(pk=protocol_id)
    except Protocol.DoesNotExist:
        messages.error(request, "Protocol not found.")
        return redirect('protocol_list')
    
    # Only the creator can update the protocol
    if protocol.created_by != request.user:
        messages.error(request, "You don't have permission to update this protocol.")
        return redirect('protocol_detail', protocol_id=protocol_id)
    
    if request.method == 'POST':
        form = ProtocolForm(request.POST, instance=protocol)
        if form.is_valid():
            # Save the previous hash before updating
            previous_hash = protocol.hash
            
            # Update the protocol
            updated_protocol = form.save(user=request.user)
            
            # Update the previous_version_hash
            updated_protocol.previous_version_hash = previous_hash
            updated_protocol.save()
            
            log_audit_event("PROTOCOL_UPDATED", f"Protocol updated: {updated_protocol.title}", f"By: {request.user.username}")
            messages.success(request, f'Protocol "{updated_protocol.title}" updated successfully.')
            return redirect('protocol_detail', protocol_id=protocol_id)
    else:
        form = ProtocolForm(instance=protocol)
    
    return render(request, 'CTPortal/protocol_form.html', {'form': form})

@login_required
def consent_create(request, protocol_id):
    # Only participants can consent
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type != 'PARTICIPANT':
            messages.error(request, "Only participants can provide consent.")
            return redirect('protocol_detail', protocol_id=protocol_id)
    except StakeholderProfile.DoesNotExist:
        messages.error(request, "You don't have a stakeholder profile.")
        return redirect('index')
    
    try:
        protocol = Protocol.objects.get(pk=protocol_id)
    except Protocol.DoesNotExist:
        messages.error(request, "Protocol not found.")
        return redirect('participant_dashboard')
    
    # Check if consent already exists
    try:
        existing_consent = Consent.objects.get(participant=request.user, protocol=protocol)
        if existing_consent.is_active:
            messages.info(request, "You have already consented to this protocol.")
        else:
            # Reactivate consent
            existing_consent.is_active = True
            existing_consent.save()
            
            # Record consent reactivation in blockchain
            consent_data = {
                'EventType': 'CONSENT_REACTIVATED',
                'ConsentID': existing_consent.id,
                'ProtocolID': protocol.id,
                'ProtocolTitle': protocol.title,
                'ParticipantID': request.user.id,
                'ParticipantUsername': request.user.username,
                'Timestamp': existing_consent.consented_at.isoformat(),
                'ConsentHash': existing_consent.consent_hash
            }
            record_blockchain_event('CONSENT_REACTIVATED', consent_data)
            
            log_audit_event("CONSENT_REACTIVATED", f"Consent reactivated for protocol: {protocol.title}", f"By: {request.user.username}")
            messages.success(request, f'You have successfully consented to participate in "{protocol.title}".') 
    except Consent.DoesNotExist:
        # Create new consent
        import hashlib
        consent_data = f"{request.user.username}|{protocol.id}|{protocol.title}"
        consent_hash = hashlib.sha256(consent_data.encode()).hexdigest()
        
        consent = Consent(
            participant=request.user,
            protocol=protocol,
            consent_hash=consent_hash,
            is_active=True
        )
        consent.save()
        
        # Record consent creation in blockchain
        blockchain_data = {
            'EventType': 'CONSENT_CREATED',
            'ConsentID': consent.id,
            'ProtocolID': protocol.id,
            'ProtocolTitle': protocol.title,
            'ParticipantID': request.user.id,
            'ParticipantUsername': request.user.username,
            'Timestamp': consent.consented_at.isoformat(),
            'ConsentHash': consent.consent_hash
        }
        record_blockchain_event('CONSENT_CREATED', blockchain_data)
        
        log_audit_event("CONSENT_CREATED", f"Consent provided for protocol: {protocol.title}", f"By: {request.user.username}")
        messages.success(request, f'You have successfully consented to participate in "{protocol.title}".')
    
    return redirect('participant_dashboard')

@login_required
def consent_revoke(request, consent_id):
    # Only participants can revoke consent
    try:
        profile = request.user.stakeholder_profile
        if profile.stakeholder_type != 'PARTICIPANT':
            messages.error(request, "Only participants can revoke consent.")
            return redirect('participant_dashboard')
    except StakeholderProfile.DoesNotExist:
        messages.error(request, "You don't have a stakeholder profile.")
        return redirect('index')
    
    try:
        consent = Consent.objects.get(pk=consent_id, participant=request.user)
    except Consent.DoesNotExist:
        messages.error(request, "Consent not found or you don't have permission to revoke it.")
        return redirect('participant_dashboard')
    
    if not consent.is_active:
        messages.info(request, "This consent has already been revoked.")
        return redirect('participant_dashboard')
    
    # Revoke consent
    consent.is_active = False
    consent.save()
    
    # Record consent revocation in blockchain
    current_time = timezone.now()
    revoke_data = {
        'EventType': 'CONSENT_REVOKED',
        'ConsentID': consent.id,
        'ProtocolID': consent.protocol.id,
        'ProtocolTitle': consent.protocol.title,
        'ParticipantID': request.user.id,
        'ParticipantUsername': request.user.username,
        'RevokedAt': current_time.isoformat(),
        'ConsentHash': consent.consent_hash
    }
    record_blockchain_event('CONSENT_REVOKED', revoke_data)
    
    log_audit_event("CONSENT_REVOKED", f"Consent revoked for protocol: {consent.protocol.title}", f"By: {request.user.username}")
    messages.success(request, f'You have successfully revoked your consent for "{consent.protocol.title}".')
    
    return redirect('participant_dashboard')
