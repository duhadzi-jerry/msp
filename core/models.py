import random
import string
from django.db import models
from django.contrib.auth.models import User as BaseUser

def generate_username():
    return f"MSP-" + ''.join(random.choices(string.digits, k=6))

# Create your models here.
class User(BaseUser):
    hold = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.username = generate_username()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.username

class SynergyApplication(models.Model):
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=50, blank=True, null=True)
    pitch = models.TextField(max_length=300)
    cv = models.FileField(upload_to='synergy_cvs/', blank=True, null=True)
    date_submitted = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.full_name} ({self.email})"