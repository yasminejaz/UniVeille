"""djangoProject1 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include
from CVE_BD import views
from django.urls import re_path as url

from CVE_BD.views import UserLoginView, UserActifView
from djangoProject1 import settings
from django.contrib.staticfiles.urls import staticfiles_urlpatterns




urlpatterns = [
    path('',views.page_presentative, name=''),
    path('accounts/', include('django.contrib.auth.urls')),
    path('admin/', admin.site.urls),
    path('cve/', views.donnees),
    path('home/', views.homepage , name ='home'),
    path(r'cve/<cve_id>', views.abdelhak , name='cve'),
    path('cve_unique/', views.cve_unique),
    path('searchdata/',views.test),
    path('assets/', views.assets),
    path('assets_cve/',views.assets_cve_newtable ),
    path('client/',views.client , name ='client'),
    path('not_authorized/',views.non_autorise , name ='not_authorized'),
    path('recherche/',views.recherche_filtre ),
    path(r'vuln/<cve_id>', views.une_cve , name='vuln'),
    path(r'vuln_affected/<cve_id>/<actif_aff>', views.une_cve_affected , name='vuln_affected'),
    path('pdf/<cve_id>/<actif_affected>',views.download_pdf, name="download_pdf"),

    path('accounts/signup/',views.signup,name='signup'),
    path('hello/', views.filtrer_par_date),
    path('login/',views.loginPage, name='login'),

    path(r'^logout', views.log_out ,name='log_out'),
    path('workflowPage/',views.workflowPage),
    path('dashboard/',views.dashboard_admin),
    path('dashboard_gerer-client/',views.dashboard_gere_client),
    path('dashboard_entreprises/',views.dashboard_entreprises),
    path('explorer/', views.explorer),
    path('explorer/<cve_id>', views.explorer_cve,name='Explorer'),
    path('explorer_recherche/', views.explorer_recherche,name='cherche'),
    path('app/',views.download_exe, name="download_exe"),
    path('api/upload_actif/', UserActifView.as_view()),
    path('api/login/', UserLoginView.as_view()),





]
urlpatterns += staticfiles_urlpatterns()