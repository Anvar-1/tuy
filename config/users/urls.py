from django.urls import path
from .views import UserCreateView, UserAuthToken, LoginAPIView, LogOutAPIView, UserDeleteView, UserUpdateView, \
    VerifyCodeAPIView, ChangeUserInformationView, UserProfileView, SendCodeView, VerifyCodeView, ResetPasswordView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.views import TokenBlacklistView



urlpatterns = [
    path('register/', UserCreateView.as_view(), name='user-register'),
    path('login/', LoginAPIView.as_view(), name='login'),
    path('logout/', LogOutAPIView.as_view(), name='logout'),
    path('delete/', UserDeleteView.as_view(), name='delete'),
    path('update/', UserUpdateView.as_view(), name='update'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('confirm-code/', VerifyCodeAPIView.as_view(), name='verify_code'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('change-user/', ChangeUserInformationView.as_view(), name='change-user'),
    path('token/blacklist/', TokenBlacklistView.as_view(), name='token_blacklist'),
    path('send-code/', SendCodeView.as_view(), name='send-code'),
    path('verify-code/', VerifyCodeView.as_view(), name='verify-code'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),

]