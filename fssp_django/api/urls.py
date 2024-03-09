# URLs for the api 
from django.urls import path

from . import views

urlpatterns = [
    #path('', views.index, name='index'),
    path( 'change_unverifiable_email', views.changeUnverifiedEmail, name='change_unverified_email'),
    path('get_files', views.getFiles, name='get_files'),
    path('get_user_details', views.getUserDetails, name='get_user_details'),
    path('get_profile_pic', views.getProfilePic, name='get_profile_pic'),
    path('register', views.register, name='register'),
    path('login', views.login, name='login'),
    path('forgotPassword', views.forgotPassword, name='forgotPassword'),
    path('resetPassword', views.resetPassword, name='resetPassword'),
    path('logout', views.logout, name='logout'),
    path('check_session', views.check_session, name='check_session'),
    path('verifyEmail/<uidb64>/<token>', views.verifyEmail, name='verifyEmail'),
]