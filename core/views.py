import re
from django.conf import settings
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.core.paginator import Paginator
from .models import *
from .form import *
from django.views import View
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.timezone import now
import requests, json
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.core.mail import EmailMultiAlternatives, get_connection
import imaplib, email
from email.utils import parseaddr, parsedate_to_datetime
from django.utils import timezone

from .models import Emails, EmailMessage


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password')

        if not username or not password:
            messages.error(request, 'Enter both username and password.', extra_tags='alert alert-warning')
            return redirect('login')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user:
                login(request, user)
                messages.success(request, f'Welcome back, {user.username}!', extra_tags='alert alert-success')
                return redirect('msp_specialist')
            else:
                messages.error(request, 'Unauthorized role.', extra_tags='alert alert-danger')
        else:
            messages.error(request, 'Invalid credentials.', extra_tags='alert alert-danger')

        return redirect('login')

    return render(request, 'core/login.html')

def forgot_password(request):
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
                token = default_token_generator.make_token(user)
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                reset_password_link = request.build_absolute_uri(
                    reverse_lazy('reset_password', kwargs={'uidb64': uidb64, 'token': token})
                )
                context = {
                    'reset_password_link': reset_password_link,
                }

                subject = "Password Reset"
                html_message = render_to_string('core/password_reset.html', context)
                plain_message = strip_tags(html_message)
                recipient_list = [user.email]

                # Create custom SMTP connection for password reset
                connection = get_connection(
                    host="mirjy.com",
                    port=465,
                    username="no-reply@mirjy.com",
                    password="the company&noreply",
                    use_ssl=True,
                )
                # Build email
                email_message = EmailMultiAlternatives(
                    subject=subject,
                    body=plain_message,
                    from_email="Mirjy Technologies Ltd <no-reply@mirjy.com>",
                    to=recipient_list,
                    connection=connection,
                )
                email_message.attach_alternative(html_message, "text/html")
                # Send the email
                email_message.send(fail_silently=False)
                messages.success(request, 'A reset link has been sent to your email', extra_tags='alert alert-success')
                return redirect('login')

            except User.DoesNotExist:
                messages.error(request, 'No user found with this email', extra_tags='alert alert-danger')

    else:
        form = ForgotPasswordForm()

    return render(request, 'core/forgotPassword.html', {'form': form})

class PasswordResetConfirmView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and default_token_generator.check_token(user, token):
            form = PasswordResetForm(user=user)
            context = {
                'form': form,
                'uidb64': uidb64,
                'token': token,
            }
            return render(request, 'core/resetPassword.html', context)

        else:
            messages.error(request, 'Password reset link invalid', extra_tags='alert alert-warning')
            return redirect('forgot_password')

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and default_token_generator.check_token(user, token):
            form = PasswordResetForm(user=user, data=request.POST)

            if form.is_valid():
                form.save()
                messages.success(request, 'Password reset successful', extra_tags='alert alert-success')
                return redirect('login')

            else:
                return render(request, 'core/admin/resetPassword.html', {'form': form, 'uidb64': uidb64, 'token': token})

        else:
            messages.error(request, 'Password reset link invalid', extra_tags='alert alert-warning')
            return redirect('forgot_password')

def logout_view(request):
    logout(request)
    
    messages.success(request, "Logged out successfully.", extra_tags='alert alert-success')
    return redirect('login')


def msp_home(request):
    return render(request, 'core/msp_home.html')


def msp_specialist(request):
    users = SynergyApplication.objects.filter(status=False)
    leads = Lead.objects.filter(created_by=User.objects.get(username=request.user))
    lead_form = LeadForm()

    admin_leads_count = Lead.objects.filter(created_by__assign_to=request.user.username)


    # Pagination
    paginator = Paginator(leads, 10)  # Show 10 leads per page
    page_number = request.GET.get('page')
    leads_page = paginator.get_page(page_number)

    # Pagination
    paginator = Paginator(admin_leads_count, 1)  # Show 10 leads per page
    page_number = request.GET.get('page')
    admin_leads_page = paginator.get_page(page_number)

    paginator = Paginator(users, 10)  # Show 10 users per page
    users_page_number = request.GET.get('page')
    users_page = paginator.get_page(users_page_number)
    

    resources = Resource.objects.all()
    announcements = Announcement.objects.all().last()

    # top_specialists = User.objects.filter(client_acquired__gte=3).order_by('-client_acquired')[:3]
    # top_specialist_1 = top_specialists[0] if len(top_specialists) > 0 else None
    # top_specialist_2 = top_specialists[1] if len(top_specialists) > 1 else None
    # top_specialist_3 = top_specialists[2] if len(top_specialists) > 2 else None

    # leads.filter(client=True).count()


    context = {
        'user': User.objects.get(username=request.user),
        'users': users_page,
        'leads': leads_page,
        'admin_leads':admin_leads_page,
        'lead_form': lead_form,
        'resources': resources,
        'announcements': announcements,
        # 'top_specialist_1': top_specialist_1,
        # 'top_specialist_2': top_specialist_2,
        # 'top_specialist_3': top_specialist_3,
        'active_leads': leads.filter(status=True).count(),
        'active_leads_percent': (leads.filter(status=True).count() / leads.count() * 100) if leads.count() > 0 else 0,
        'inactive_leads': leads.filter(status=False).count(),
        'inactive_leads_percent': (leads.filter(status=False).count() / leads.count() * 100) if leads.count() > 0 else 0,
        'drop_leads': leads.filter(drop=True).count(),
        'drop_leads_percent': (leads.filter(drop=True).count() / leads.count() * 100) if leads.count() > 0 else 0,
        'client_acquired': leads.filter(client=True).count(),
        'client_acquired_percent': (leads.filter(client=True).count() / leads.count() * 100) if leads.count() > 0 else 0,

        'admin_active_lead': admin_leads_count.filter(status=True),
        'admin_active_leads': admin_leads_count.filter(status=True).count(),
        'admin_active_leads_percent': (admin_leads_count.filter(status=True).count() / admin_leads_count.count() * 100) if admin_leads_count.count() > 0 else 0,
        'admin_inactive_lead': admin_leads_count.filter(status=False),
        'admin_inactive_leads': admin_leads_count.filter(status=False).count(),
        'admin_inactive_leads_percent': (admin_leads_count.filter(status=False).count() / admin_leads_count.count() * 100) if admin_leads_count.count() > 0 else 0,
        'admin_drop_lead': admin_leads_count.filter(drop=True),
        'admin_drop_leads': admin_leads_count.filter(drop=True).count(),
        'admin_drop_leads_percent': (admin_leads_count.filter(drop=True).count() / admin_leads_count.count() * 100) if admin_leads_count.count() > 0 else 0,
        'admin_client_acquireds': admin_leads_count.filter(client=True),
        'admin_client_acquired': admin_leads_count.filter(client=True).count(),
        'admin_client_acquired_percent': (admin_leads_count.filter(client=True).count() / admin_leads_count.count() * 100) if admin_leads_count.count() > 0 else 0,


    }
    return render(request, 'core/msp_specialist.html', context)

def submit_synergy_application(request):
    if request.method == 'POST':
        form = SynergyApplicationForm(request.POST, request.FILES)
        if form.is_valid():
            application = form.save()

            applicant_email = form.cleaned_data.get('email')
            applicant_name = form.cleaned_data.get('full_name') 
            content = """
                Thank you for applying to the Mirjy Synergy Program.
                We have received your application and our team will review it shortly.
                
            """

            # Render HTML
            html_message = render_to_string(
                'core/email_temp.html',
                {
                    'name': applicant_name,
                    'content': content,
                    'date': now(),
                    'email': settings.DEFAULT_FROM_EMAIL
                }
            )
            plain_message = strip_tags(html_message)  # fallback for plain text clients

            # Send email
            if applicant_email:
                send_mail(
                    subject="Mirjy Synergy Program Application",
                    message=plain_message,
                    from_email=f"Mirjy Technologies Ltd <{settings.DEFAULT_FROM_EMAIL}>",
                    recipient_list=[applicant_email],
                    fail_silently=False,
                    html_message=html_message,
                )

            return JsonResponse({'status': 'success', 'message': 'Application submitted successfully!'}, status=200)
        
        return JsonResponse({'status': 'error', 'errors': form.errors}, status=400)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


def approve_synergy_application(request, application_id):
    try:
        application = SynergyApplication.objects.get(id=application_id)
        application.status = True
        application.save()

        User.objects.create_user(
            username=application.full_name,
            email=application.email,
            password='welcomeCAS',
        )

        user = User.objects.get(email=application.email)

        # Send approval email
        content = f"""
                We are excited to imform you that you have being approved for the Mirjy Synergy Program.
                We will be in touch with you shortly to discuss the next steps.
                Your login information:
                Username: {user.username}, Password: welcomeCAS
            """

            # Render HTML
        html_message = render_to_string(
            'core/email_temp.html',
            {
                'name': application.full_name,
                'content': content,
                'date': now(),
                'email': settings.DEFAULT_FROM_EMAIL
            }
        )
        plain_message = strip_tags(html_message)

        # Send email
        if application.email:
            send_mail(
                subject="Mirjy Synergy Program Application",
                message=plain_message,
                from_email=f"Mirjy Technologies Ltd <{settings.DEFAULT_FROM_EMAIL}>",
                recipient_list=[application.email],
                fail_silently=False,
                html_message=html_message,
            )

        messages.success(request, 'Application approved successfully.', extra_tags='alert alert-success')
    except SynergyApplication.DoesNotExist:
        messages.error(request, 'Application not found.', extra_tags='alert alert-warning')

    return redirect('msp_specialist')

def reject_synergy_application(request, application_id):
    try:
        application = SynergyApplication.objects.get(id=application_id)
        application.status = True
        application.save()

        # Send rejection email
        content = """
                We regret to inform you that your application for the Mirjy Synergy Program has been rejected.
                We appreciate your interest and encourage you to apply again in the future.
            """

        # Render HTML
        html_message = render_to_string(
            'core/email_temp.html',
            {
                'name': application.full_name,
                'content': content,
                'date': now(),
                'email': settings.DEFAULT_FROM_EMAIL
            }
        )
        plain_message = strip_tags(html_message)

        # Send email
        if application.email:
            send_mail(
                subject="Mirjy Synergy Program Application",
                message=plain_message,
                from_email=f"Mirjy Technologies Ltd <{settings.DEFAULT_FROM_EMAIL}>",
                recipient_list=[application.email],
                fail_silently=False,
                html_message=html_message,
            )

        messages.success(request, 'Application rejected successfully.', extra_tags='alert alert-success')
    except SynergyApplication.DoesNotExist:
        messages.error(request, 'Application not found.', extra_tags='alert alert-warning')

    return redirect('msp_specialist')

def submit_lead(request):
    if request.method == 'POST':
        form = LeadForm(request.POST)
        if form.is_valid():
            lead = form.save(commit=False)
            lead.created_by = User.objects.get(username=request.user)
            lead.save()
            messages.success(request, 'Lead added successfully.', extra_tags='alert alert-success')
            return redirect('msp_specialist')
        else:
            messages.error(request, 'Error adding lead. Please correct the errors below.', extra_tags='alert alert-warning')

    else:
        form = LeadForm()

    return render(request, 'core/add_lead.html', {'form': form})

def convert_lead_to_client(request, lead_id):
    try:
        lead = Lead.objects.get(id=lead_id)
        lead.status = False
        lead.client = True  # Mark lead as inactive
        lead.save()

        messages.success(request, 'Lead converted to client successfully.', extra_tags='alert alert-success')
    except Lead.DoesNotExist:
        messages.error(request, 'Lead not found.', extra_tags='alert alert-warning')

    return redirect('msp_specialist')

def drop_lead(request, lead_id):
    try:
        lead = Lead.objects.get(id=lead_id)
        lead.status = False
        lead.drop = True 
        lead.save()

        messages.success(request, 'Lead dropped successfully.', extra_tags='alert alert-success')
    except Lead.DoesNotExist:
        messages.error(request, 'Lead not found.', extra_tags='alert alert-warning')

    return redirect('msp_specialist')

def upload_resource(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        file = request.FILES.get('file')

        if not title or not file:
            messages.error(request, 'Title and file are required.', extra_tags='alert alert-warning')
            return redirect('upload_resource')

        resource = Resource(title=title, file=file)
        resource.save()

        messages.success(request, 'Resource uploaded successfully.', extra_tags='alert alert-success')
        return redirect('msp_specialist')

def delete_resource(request, resource_id):
    try:
        resource = Resource.objects.get(id=resource_id)
        resource.delete()
        messages.success(request, 'Resource deleted successfully.', extra_tags='alert alert-success')
    except Resource.DoesNotExist:
        messages.error(request, 'Resource not found.', extra_tags='alert alert-warning')

    return redirect('msp_specialist')

def delete_announcement(request, announcement_id):
    try:
        announcement = Announcement.objects.get(id=announcement_id)
        announcement.delete()
        messages.success(request, 'Announcement deleted successfully.', extra_tags='alert alert-success')
    except Announcement.DoesNotExist:
        messages.error(request, 'Announcement not found.', extra_tags='alert alert-warning')

    return redirect('msp_specialist')

def add_announcement(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')

        if not title or not content:
            messages.error(request, 'Title and content are required.', extra_tags='alert alert-warning')
            return redirect('add_announcement')

        announcement = Announcement(title=title, content=content)
        announcement.save()

        messages.success(request, 'Announcement added successfully.', extra_tags='alert alert-success')
        return redirect('msp_specialist')



# -------------------
# List Contacts
# -------------------
    
@login_required
def chat_app(request):
    contacts = Contact.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "core/chat_app.html", {"contacts": contacts})

@login_required
def email_app(request):
    get_mailbox_emails(request, 'mirjy.com', 'client-acquisition@mirjy.com', 'the company&cas')
    emails = Emails.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "core/email_app.html", {"emails": emails,})

def add_contact(request):
    if request.method == "POST":
        name = request.POST.get("name")
        phone = request.POST.get("phone")

        if not name or not phone:
            messages.error(request, "Name and phone are required.", extra_tags='alert alert-warning')
            return redirect("chat_app")
        
        if phone.startswith("0") and len(phone) == 10:
            phone = "+233" + phone[1:]
        elif phone.startswith("233") and len(phone) == 12:
            phone = "+" + phone
        elif phone.startswith("+233") and len(phone) == 13:
            phone = phone
        elif len(phone) == 9:
            phone = "+233" + phone
        else:
            messages.error(request, "Invalid Ghana phone number format.", extra_tags='alert alert-warning')
            return redirect("chat_app")

        if Contact.objects.filter(phone=phone).exists():
            messages.error(request, "This phone number already exists.", extra_tags='alert alert-warning')
            return redirect("chat_app")

        Contact.objects.create(user=User.objects.get(username=request.user), name=name, phone=phone)
        return redirect("chat_app")
    
    messages.error(request, "Invalid request method.", extra_tags='alert alert-warning')
    return redirect("chat_app")

def add_email(request):
    if request.method == "POST":
        name = request.POST.get("name")
        phone = request.POST.get("phone")

        if not name or not phone:
            messages.error(request, "Name and phone are required.", extra_tags='alert alert-warning')
            return redirect("email_app")

        if Emails.objects.filter(email=phone).exists():
            messages.error(request, "This email already exists.", extra_tags='alert alert-warning')
            return redirect("email_app")

        Emails.objects.create(user=User.objects.get(username=request.user), name=name, email=phone)
        return redirect("email_app")

    messages.error(request, "Invalid request method.", extra_tags='alert alert-warning')
    return redirect("email_app")
# -------------------
# Send WhatsApp Message
# -------------------
@login_required
def send_message(request, contact_id):
    if request.method == "POST":
        contact = get_object_or_404(Contact, id=contact_id, user=request.user)
        message = request.POST.get("message")

        # Store message locally first
        msg = Message.objects.create(contact=contact, direction="outgoing", content=message)

        # Call WhatsApp Cloud API
        url = f"https://graph.facebook.com/v20.0/{settings.WHATSAPP_PHONE_NUMBER_ID}/messages"
        headers = {
            "Authorization": f"Bearer {settings.WHATSAPP_ACCESS_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = {
            "messaging_product": "whatsapp",
            "to": contact.phone,
            "type": "text",
            "text": {"body": message}
        }
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code in [200, 201]:
            return JsonResponse({"status": "sent", "message": message})
        else:
            return JsonResponse({"status": "error", "details": response.text}, status=400)

# -------------------
# Webhook (WhatsApp → Django)
# -------------------
@csrf_exempt
def whatsapp_webhook(request):
    if request.method == "GET":
        # For Meta webhook verification
        verify_token = settings.WHATSAPP_VERIFY_TOKEN
        mode = request.GET.get("hub.mode")
        challenge = request.GET.get("hub.challenge")
        token = request.GET.get("hub.verify_token")

        if mode == "subscribe" and token == verify_token:
            return HttpResponse(challenge)
        return HttpResponse("Verification failed", status=403)

    elif request.method == "POST":
        data = json.loads(request.body)

        try:
            entry = data["entry"][0]
            changes = entry["changes"][0]["value"]
            messages = changes.get("messages", [])

            if messages:
                msg = messages[0]
                from_number = msg["from"]
                text = msg.get("text", {}).get("body", "")

                # Match to a contact
                contact = Contact.objects.filter(phone=from_number).first()
                if contact:
                    Message.objects.create(contact=contact, direction="incoming", content=text)

        except Exception as e:
            print("Webhook error:", e)

        return JsonResponse({"status": "received"})
    
def send_email(request, contact_id):
    if request.method == "POST":
        mail = get_object_or_404(Emails, id=contact_id, user=request.user)
        message = request.POST.get("message", "")
        file = request.FILES.get("file")

        # Store message locally first
        msg = EmailMessage.objects.create(
            email=mail,
            direction="outgoing",
            content=message,
            created_by=User.objects.get(username=request.user),
        )

        try:
            # Render HTML
            html_message = render_to_string(
                "core/email_temp.html",
                {
                    "name": mail.name,
                    "content": message,
                    "date": now(),
                    "email": settings.DEFAULT_FROM_EMAIL,
                },
            )
            plain_message = strip_tags(html_message)

            # Create a custom SMTP connection for client-acquisition
            connection = get_connection(
                host="mirjy.com",
                port=465,
                username="client-acquisition@mirjy.com",
                password="the company&cas",
                use_ssl=True,
            )

            # Build the email
            email = EmailMultiAlternatives(
                subject="Message from Mirjy Technologies",
                body=plain_message,
                from_email="Mirjy Technologies Ltd <client-acquisition@mirjy.com>",
                to=[mail.email],
                connection=connection,
            )
            email.attach_alternative(html_message, "text/html")

            # If file is uploaded, attach it
            if file:
                email.attach(file.name, file.read(), file.content_type)

            # Send email
            email.send(fail_silently=False)

            return JsonResponse({"status": "sent"})

        except Exception as e:
            return JsonResponse({"status": "error", "error": str(e)})

    return JsonResponse({"status": "error", "error": "Invalid request"})


# -------------------
# Fetch Messages for Contact (AJAX polling)
# -------------------
@login_required
def get_messages(request, contact_id):
    contact = get_object_or_404(Contact, id=contact_id, user=request.user)
    msgs = contact.messages.filter(created_by=request.user).order_by("timestamp").values("id", "direction", "content", "timestamp", "read", "created_by")
    return JsonResponse(list(msgs), safe=False)


@login_required
def get_emails(request, contact_id):
    email_obj = get_object_or_404(Emails, id=contact_id, user=request.user)

    # Mark all incoming messages as read
    email_obj.email_messages.filter(direction="incoming", read=False).update(read=True)

    # Fetch messages to return
    msgs = email_obj.email_messages.filter(created_by=request.user).order_by("timestamp").values(
        "id", "direction", "content", "timestamp", "read", "created_by"
    )

    return JsonResponse(list(msgs), safe=False)

import re

def clean_email_body(body: str) -> str:
    """
    Extract only the latest reply (removes quoted text and signatures,
    including common mobile signatures like 'Sent from my iPhone').
    """
    # Normalize newlines
    body = body.replace("\r\n", "\n").strip()

    # Split on common reply markers
    reply_markers = [
        r"\nOn .* wrote:",
        r"\nFrom:.*",
        r"-----Original Message-----",
    ]
    for marker in reply_markers:
        match = re.search(marker, body, flags=re.IGNORECASE | re.DOTALL)
        if match:
            body = body[:match.start()].strip()
            break

    # Remove any lines starting with '>'
    lines = []
    for line in body.split("\n"):
        if not line.strip().startswith(">"):
            lines.append(line)
    body = "\n".join(lines)

    # Remove signatures and mobile footers
    signature_patterns = [
        r"--+\s*.*",                  # traditional "--" signatures
        r"Sent from my .*",           # mobile signatures ("Sent from my iPhone/Android/Pixel/etc.")
        r"Get Outlook for .*",        # Outlook mobile signature
    ]
    for pattern in signature_patterns:
        body = re.sub(pattern, "", body, flags=re.IGNORECASE | re.DOTALL)

    # Final cleanup
    body = re.sub(r"\n{2,}", "\n\n", body).strip()

    return body


def get_mailbox_emails(request, EMAIL_HOST, EMAIL_USER, EMAIL_PASS):
    try:
        mail = imaplib.IMAP4_SSL(EMAIL_HOST)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select('inbox')

        _, data = mail.search(None, 'ALL')
        mail_ids = data[0].split()

        for num in reversed(mail_ids[-30:]):  # fetch last 30 to reduce load
            _, msg_data = mail.fetch(num, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])

                    # Decode subject safely
                    subject, enc = email.header.decode_header(msg.get('Subject', ''))[0]
                    if isinstance(subject, bytes):
                        subject = subject.decode(enc or 'utf-8', errors='ignore')

                    # Parse sender
                    from_ = msg.get('From', '')
                    _, from_email = parseaddr(from_)

                    # Parse date
                    try:
                        parsed_date = parsedate_to_datetime(msg.get('Date'))
                        if parsed_date and timezone.is_naive(parsed_date):
                            parsed_date = timezone.make_aware(parsed_date, timezone.get_default_timezone())
                    except Exception:
                        parsed_date = timezone.now()

                    # Extract body
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain" and not part.get('Content-Disposition'):
                                body = part.get_payload(decode=True).decode(errors='ignore')
                                break
                    else:
                        body = msg.get_payload(decode=True).decode(errors='ignore')

                    # Match sender to Emails table
                    body = clean_email_body(body)
                    contact = Emails.objects.filter(email__iexact=from_email).first()
                    if contact:
                        # Avoid duplicates
                        exists = EmailMessage.objects.filter(
                            email=contact,
                            content__startswith=body[:50],
                            timestamp__date=parsed_date.date(),
                            created_by=User.objects.get(username=request.user)
                        ).exists()

                        if not exists:
                            EmailMessage.objects.create(
                                email=contact,
                                direction="incoming",
                                content=f"{body}",
                                timestamp=parsed_date,
                                created_by=User.objects.get(username=request.user)
                            )

        mail.logout()

    except Exception as e:
        print(f"Error fetching emails: {e}")
