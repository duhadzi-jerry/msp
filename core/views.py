from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render, redirect 
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

# Create your views here.

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip().lower()
        password = request.POST.get('password')

        if not username or not password:
            messages.error(request, 'Enter both username and password.')
            return redirect('login')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            if user:
                login(request, user)
                messages.success(request, f'Welcome back, {user.username}!')
                return redirect('msp_specialist')
            else:
                messages.error(request, 'Unauthorized role.')
        else:
            messages.error(request, 'Invalid credentials.')

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
                reset_password_link = request.build_absolute_uri(reverse_lazy('reset_password', kwargs={'uidb64': uidb64, 'token': token}))

                context = {
                    'reset_password_link': reset_password_link,
                }
                
                subject = "Password Reset"
                html_message = render_to_string('emails/password_reset.html', context)
                plain_message = strip_tags(html_message)
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [user.email]

                # Send the email
                send_mail(subject, plain_message, email_from, recipient_list, html_message=html_message, fail_silently=False)

                messages.success(request, 'A reset link has been sent to your email', extra_tags='alert alert-success')
                return redirect('login')
            except User.DoesNotExist:
                pass
    else:
        form = ForgotPasswordForm()
    return render(request, 'core/admin/forgotPassword.html', {'form': form})

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
            return render(request, 'core/admin/resetPassword.html', context)

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
    
    messages.success(request, "Logged out successfully.")
    return redirect('login')



def msp_home(request):
    return render(request, 'core/msp_home.html')


def msp_admin(request):
    # if not request.user.is_authenticated or not request.user.is_staff:
    #     return redirect('login')

    # Fetch all users
    users = SynergyApplication.objects.all()

    # Pagination
    paginator = Paginator(users, 10)  # Show 10 users per page
    page_number = request.GET.get('page')
    users_page = paginator.get_page(page_number)

    context = {
        'users': users_page,
    }
    return render(request, 'core/msp_admin.html', context)

def msp_specialist(request):
    # if not request.user.is_authenticated or not request.user.is_staff:
    #     return redirect('login')

    # Fetch all users
    users = SynergyApplication.objects.all()

    # Pagination
    paginator = Paginator(users, 10)  # Show 10 users per page
    page_number = request.GET.get('page')
    users_page = paginator.get_page(page_number)

    context = {
        'users': users_page,
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