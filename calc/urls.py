from django.urls import path
from django.contrib.auth import views as auth_views
from .import views

urlpatterns = [
    path('', views.logint,name='logint'),
    path('home/', views.home,name='home'),
    path('about/', views.about,name='about'),
    path('services/', views.services,name='services'),
    path('learn_more/',views.learn_more,name='learn_more'),
    path('logout/',views.logout,name='logout'),
    path('adminlogout/',views.adminlogout,name='adminlogout'),
    path('registred1/',views.registred_members1,name='registred1'),
    path('registred/',views.registred_members,name='registred'),
    path('admino/',views.admin_login,name='admino'),
    path('edit/',views.edit_page,name='edit'),
    path('deleter-ecord/<int:id>',views.delete_record,name='delete_record'),
    path('update-ecord/<int:id>',views.update_record,name='update_record'),
    path('insert',views.insert_tab,name='insertrecord'),
    path('signup',views.signup,name='signup'),
    path('signup-form/',views.login_form,name ='signupform'),
    path('user_reset/<id>', views.UserReset.as_view(template_name='mainpage/password_reset_form.html')),







    path('reset_password/',auth_views.PasswordResetView.as_view(template_name='forgotpassword.html'),name = 'reset_password'),
    path('reset_password_sent/',auth_views.PasswordResetDoneView.as_view(template_name='mainpage\password_reset_sent.html'),name = 'password_reset_done'),
    path('reset/<uidb64>/<token>/',auth_views.PasswordResetConfirmView.as_view(template_name='mainpage\password_reset_form.html'),name = 'password_reset_confirm'),
    path('user_reset_password/',views.UserForgot,name='user_reset_password'),
    path('reset_password_complete/',auth_views.PasswordResetCompleteView.as_view(template_name='mainpage\password_reset_done.html'),name = 'password_reset_complete'),
]
