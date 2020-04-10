from django.db import models

# Create your models here.

class Registred(models.Model):

    Year = models.IntegerField()
    Name = models.CharField(max_length=50)
    ID = models.IntegerField()
    Membership = models.CharField(max_length=50)



class LoginForm(models.Model):
    user = models.CharField(max_length=50)
    password = models.CharField(max_length=50)
    mail = models.CharField(max_length=50)
    phone = models.CharField(max_length=50)
