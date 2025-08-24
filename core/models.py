import random
import string
from django.db import models
from django.contrib.auth.models import User as BaseUser
from django.core.validators import RegexValidator

def generate_username():
    return f"MSP-" + ''.join(random.choices(string.digits, k=6))


phone_validator = RegexValidator(
    r'^\+233\d{9}$',
    message="Enter a valid WhatsApp number in the format +233XXXXXXXXX (e.g., +233591234567)."
)

# Create your models here.
class User(BaseUser):
    hold = models.BooleanField(default=False)
    admin = models.BooleanField(default=False)
    super_admin = models.BooleanField(default=False)
    assign_to = models.CharField(max_length=255)

    def save(self, *args, **kwargs):
        if not self.pk:
            self.username = generate_username()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.username
    
class Commision(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.amount} on {self.date}"

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
    

class Lead(models.Model):
    name = models.CharField(max_length=200)
    email = models.EmailField(blank=True)
    phone = models.CharField(max_length=20, blank=True)
    notes = models.TextField(blank=True)
    status = models.BooleanField(default=True)
    client = models.BooleanField(default=False)
    drop = models.BooleanField(default=False)
    joined_on = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leads')

    def __str__(self):
        return f"{self.name} - {self.created_by.username}"

class Resource(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='resources/')

    def __str__(self):
        return self.title

class Announcement(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()

    def __str__(self):
        return self.title

class Contact(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # created_by
    name = models.CharField(max_length=200)
    phone = models.CharField(max_length=20, validators=[phone_validator])  # must be in WhatsApp international format
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.phone})"
    
class Emails(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # created_by
    name = models.CharField(max_length=200)
    email = models.EmailField()  # must be in WhatsApp international format
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name}, {self.user} ({self.email})"
    
    @property
    def new_message_count(self):
        return self.email_messages.filter(direction="incoming", read=False).count()

class Message(models.Model):
    contact = models.ForeignKey(Contact, on_delete=models.CASCADE, related_name="messages")
    direction = models.CharField(max_length=10, choices=(("outgoing", "Outgoing"), ("incoming", "Incoming")))
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE, related_name='msg_sender')

    def __str__(self):
        return f"{self.direction} - {self.contact.name}: {self.content[:30]}"

class EmailMessage(models.Model):
    email = models.ForeignKey(Emails, on_delete=models.CASCADE, related_name="email_messages")
    direction = models.CharField(max_length=10, choices=(("outgoing", "Outgoing"), ("incoming", "Incoming")))
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    read = models.BooleanField(default=False)
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE, related_name='email_sender')

    def __str__(self):
        return f"{self.direction} - {self.email.name}, {self.created_by}: {self.content[:30]}"