from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    # Original routes
    path('', views.index, name='index'),
    path('SaveBlock', views.SaveBlock, name='SaveBlock'),
    path('initialize_blockchain', views.initialize_new_blockchain, name='initialize_blockchain'),
    path('block/<int:block_idx>/', views.view_block_detail, name='view_block_detail'),
    path('tamper_block/<int:block_idx>/', views.tamper_block, name='tamper_block'),
    path('verify_chain/', views.verify_chain_view, name='verify_chain'),
    path('blockchain/', views.blockchain_view, name='blockchain_view'),
    path('public_portal/', views.public_portal_view, name='public_portal'),
    path('audit_log/', views.audit_log_view, name='audit_log'),
    
    # Authentication routes
    path('login/', views.custom_login, name='login'),
    path('logout/', views.custom_logout, name='logout'),
    path('register/', views.register, name='register'),
    
    # Stakeholder-specific dashboards
    path('dashboard/conductor/', views.conductor_dashboard, name='conductor_dashboard'),
    path('dashboard/oversight/', views.oversight_dashboard, name='oversight_dashboard'),
    path('dashboard/participant/', views.participant_dashboard, name='participant_dashboard'),
    
    # Protocol management
    path('protocols/', views.protocol_list, name='protocol_list'),
    path('protocols/new/', views.protocol_create, name='protocol_create'),
    path('protocols/<int:protocol_id>/', views.protocol_detail, name='protocol_detail'),
    path('protocols/<int:protocol_id>/update/', views.protocol_update, name='protocol_update'),
    
    # Consent management
    path('consent/<int:protocol_id>/', views.consent_create, name='consent_create'),
    path('consent/<int:consent_id>/revoke/', views.consent_revoke, name='consent_revoke'),
]