from django.urls import path

from account.views import UserListView, UserLoginView, UserRegistrationView

urlpatterns = [
    path('', UserListView.as_view()),
    path('register/', UserRegistrationView.as_view()),
    path('login/', UserLoginView.as_view()),
]
