# Import authentication views
from .views_auth import (
    register, 
    conductor_dashboard, 
    oversight_dashboard, 
    participant_dashboard,
    protocol_list,
    protocol_create,
    protocol_detail,
    protocol_update,
    consent_create,
    consent_revoke
)

# Import these into the main views.py file to make them available for URL routing
