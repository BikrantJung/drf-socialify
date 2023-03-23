from django.urls import path

from account.views import UserListView

urlpatterns = [
    path('', UserListView.as_view())
]
