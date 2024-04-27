# URLs for the api 
from django.urls import path

from . import views

urlpatterns = [
    #path('', views.index, name='index'),
    # CSRF related paths
    path('gen_csrf_token', views.genCSRFToken, name='gen_csrf_token'),
    path('get_csrf_token', views.getCSRFToken, name='get_csrf_token'),
    path('check_session', views.check_session, name='check_session'),
    
    # Account settings related paths
    path('change_password', views.changePassword, name='change_password'),
    path('change_profile_pic', views.changeProfilePic, name='change_profile_pic'),
    path('edit_session_timeout', views.editSessionExpiry, name='edit_session_expiry'),

    # File related paths
    path('list_files', views.getFiles, name='get_files'),
    path('add_file', views.addFile, name='add_file'),
    path('delete_file', views.deleteFile, name='delete_file'),
    path('share_file', views.shareFile, name='share_file'),
    path('revoke_file', views.revokeSharedFile, name='revoke_file'),
    path('download_file', views.downloadFile, name='download_file'),
    path('download_shared_file', views.downloadSharedFile, name='download_shared_file'),
    path('list_shared_files', views.listSharedFiles, name='list_shared_files'),
    path('remove_access_to_file', views.removeSharedFile, name='remove_access_to_file'),

    # Owned Secret related paths
    path('add_secret', views.addSecret, name='add_secret'),
    path('list_secrets', views.listSecrets, name='list_secrets'),
    path('share_secret', views.shareSecret, name='share_secret'),
    path('revoke_secret', views.revokeSecret, name='revoke_secret'),
    path('delete_secret', views.deleteSecret, name='delete_secret'),
    path('display_secret', views.displaySecret, name='display_secret'),

    # Shared Secret related paths
    path('list_shared_secrets', views.listSharedSecrets, name='list_shared_secrets'),
    path('display_shared_secret', views.displaySharedSecret, name='display_shared_secret'),
    path('remove_access_to_secret', views.removeSharedSecret, name='remove_access_to_secret'),

    # Notifications & EventLogs related paths
    path('get_notifications', views.getNotifications, name='get_notifications'),
    path('get_user_eventlogs', views.getUserEventLogs, name='get_user_eventlogs'),
    path('get_user_eventlogs_files', views.getUserEventLogsFiles, name='get_user_eventlogs_files'),
    path('mark_notification_as_viewed', views.markNotificationAsViewed, name='mark_notification_as_viewed'),

    # User Profile related paths
    path('get_user_details', views.getUserDetails, name='get_user_details'),
    path('get_profile_pic', views.getProfilePic, name='get_profile_pic'),
    
    # Authentication related paths
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('logout', views.logout, name='logout'),
    path('change_unverifiable_email', views.changeUnverifiedEmail, name='change_unverified_email'),
    #path('forgotPassword', views.forgotPassword, name='forgotPassword'),
    path('resetPassword', views.resetPassword, name='resetPassword'),    
    path('verifyEmail/<uidb64>/<token>', views.verifyEmail, name='verifyEmail'),

    # path('', views.index, {'https': True}),
]