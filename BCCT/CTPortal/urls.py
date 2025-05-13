from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("SaveBlock", views.SaveBlock, name="SaveBlock"),
    path("tamper_block/<int:block_idx>/", views.tamper_block, name="tamper_block"),
    path("initialize_blockchain/", views.initialize_new_blockchain, name="initialize_blockchain"),
    path("view_block/<int:block_idx>/", views.view_block_detail, name="view_block_detail"),
    path("verify_chain/", views.verify_chain_view, name="verify_chain"),
    path("public/", views.public_portal_view, name="public_portal"),
    path("audit_log/", views.audit_log_view, name="audit_log"),
]