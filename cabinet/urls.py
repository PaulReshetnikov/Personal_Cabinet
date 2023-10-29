from django.urls import path
from django.views.generic import TemplateView
from .views import *
from django.contrib.auth.views import PasswordChangeView, PasswordResetView

urlpatterns = [
    path(
        'invalid_verify/',
        TemplateView.as_view(template_name='cabinet/invalid_verify.html'),
        name='invalid_verify'
    ),

    path(
        'verify_email/<uidb64>/<token>/',
        EmailVerify.as_view(),
        name='verify_email',
    ),

    path(
        'confirm_email/',
        TemplateView.as_view(template_name='cabinet/confirm_email.html'),
        name='confirm_email'
    ),

    path('register/', Register.as_view(), name='register'),
    path('login/', SignInView.as_view(), name='login'),
    path('logout/', AuthLogoutView.as_view(), name='logout'),
    path('users_list/', UserListView.as_view(), name='users_list'),
    path('profile/<uuid:pk>/', UserProfileView.as_view(), name='user_profile'),
    path('profile/edit/<uuid:pk>', EditProfileView.as_view(), name='edit_profile'),
    path('change_password/', PasswordChangeView.as_view(), name='password_change'),
    path('reset_password', PasswordResetView.as_view(), name='password_reset'),
    path('change_email/', ChangeEmailView.as_view(), name='email_change'),
]
