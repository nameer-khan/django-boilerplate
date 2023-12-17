from django.urls import path
from . import views
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
# from .views import MyTokenPairView
from .views import UserRegisterView, UserLoginView, LogoutView, MyProfileView


urlpatterns = [
    # path('',views.getRoutes),
    # path('token/', MyTokenPairView.as_view(), name='token_obtain_pair'),
    # path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', UserRegisterView.as_view()),
    path('login/', UserLoginView.as_view()),
    path('logout/',LogoutView.as_view()),
    path('my-profile/',MyProfileView.as_view())

]