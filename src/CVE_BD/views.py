import os
from contextlib import closing
from decimal import Decimal

from xhtml2pdf import pisa
import psycopg2
from django.db.models.functions import Lower
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.db import connections
from django.db.models.signals import post_save
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render, redirect
from django.template import loader
from django.template.loader import get_template

from notifications.signals import notify
from django.contrib.auth import logout, authenticate, login
from requests import auth

from .models import *
from django.db.models import Case, Value, When
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
import datetime
from datetime import date, timedelta
from django.db.models import Count
import _strptime
import csv
import pandas as pd
from django.db.models import F

from .decorators import unauthenticated_user, allowed_users, admin_only

# pour l'api

from django.http import HttpResponse

# Create your views here.
from django.template import loader
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserActifSerializer, UserDataSerializer, ActifSerializer
from .models import actifs
from secrets import compare_digest
from django.contrib.auth.models import User


# pas besoin i think
def donnees(request):
    cves = cve.objects.values('cve_id')
    cwes = cwe.objects.all().values()
    products = product.objects.all().values()
    cves_cwes = cve_cwe.objects.all().values()
    references = reference.objects.all().values()

    e = product.objects.filter(cve_id_id='CVE-2013-3325')
    f = reference.objects.filter(cve_id_id='CVE-2013-3325')
    g = cve_cwe.objects.filter(cve_id_id='CVE-2013-3325')

    list = []
    for i in cves[0:10]:
        list.append(i)
        list.append(product.objects.filter(cve_id_id=i['cve_id']))
        list.append(reference.objects.filter(cve_id_id=i['cve_id']))
        list.append(cve_cwe.objects.filter(cve_id_id=i['cve_id']))

    template = loader.get_template('cvetesthtml.html')
    context = {
        'cve': cves,
        'cwe': cwes,
        'product': products,
        'reference': references[0:20],
        'test2': f,
        'test3': e,
        'test4': g,
        'test5': list,

    }
    return HttpResponse(template.render(context, request))


# cve detaillé - pas besoin
def cve_unique(request):
    cves = cve.objects.values('cve_id')
    cwes = cwe.objects.all().values()
    products = product.objects.all().values()
    cves_cwes = cve_cwe.objects.all().values()
    references = reference.objects.all().values()

    pro = product.objects.filter(cve_id_id='CVE-2013-3325')
    ref = reference.objects.filter(cve_id_id='CVE-2013-3325')
    cwecve = cve_cwe.objects.filter(cve_id_id='CVE-2013-3325')

    template = loader.get_template('cve_unique.html')
    context = {
        'cve': cves,
        'cwe': cwecve,
        'prod': pro,
        'ref': ref,
        'cwe': cwecve,
    }

    return HttpResponse(template.render(context, request))


# dashboard
def homepage(request):
    cves = cve.objects.all().values().order_by('-date_publication')
    return render(request, 'homepage.html', {
        'data': cves[0:20],
    })


# la relation entre le dashboard
def abdelhak(request, cve_id):
    cves = cve.objects.filter(cve_id=cve_id).values().order_by('-date_publication')
    prod = product.objects.filter(cve_id_id=cve_id)
    ref = reference.objects.filter(cve_id_id=cve_id)
    cwecve = cve_cwe.objects.filter(cve_id_id=cve_id)

    template = loader.get_template('cve_unique.html')
    context = {
        'emp': cve_id,
        'cve': cves,
        'cwe': cwecve,
        'prod': prod,
        'ref': ref,
        'cwe': cwecve,
    }
    return HttpResponse(template.render(context, request))


# recherche par filtre
def test(request):
    data = request.GET['search']
    filtres = request.GET['filtre']
    if data != '':
        if (filtres == 'CVE' or filtres == ''):
            cvee = cve.objects.filter(cve_id=data).order_by('-date_publication')

        if (filtres == 'Vendor'):
            cvee = product.objects.filter(vendor=data)

        if (filtres == 'Product'):
            cvee = product.objects.filter(product=data)

        if (filtres == 'cwe'):
            cvee = cve_cwe.objects.filter(cwe_id_id=data)

        if (filtres == 'cvss2_score'):
            cvee = cve.objects.filter(cvss2_score=data).order_by('-date_publication')

        if (filtres == 'cvss3_score'):
            cvee = cve.objects.filter(cvss3_score=data).order_by('-date_publication')
    else:
        cvee = cve.objects.all().values().order_by('-date_publication')

    return render(request, 'test.html', {'data': cvee, 'filtre': filtres
                                         })


@login_required(login_url='login')
@allowed_users(allowed_roles=['clients'])
def assets(request):
    template = loader.get_template('assets.html')
    current_user = request.user
    actif = actifs.objects.filter(nom_en__employe__user_id_id=current_user.id).order_by('-id')
    vendor = ""
    product = ""
    version = ""
    os_actif = ""
    type_actif = ""
    importance = ""

    # supp_notif = notif.objects.get(id_notif=reponse).delete()
    current_date = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    if ((request.method == 'POST')):
        if request.POST.get("form_type") == 'ajout_actif':
            vendor = request.POST.get('vendor')
            vendor = vendor.strip()
            vendor = vendor.replace(" ", "_")
            vendor = vendor.lower()
            product = request.POST.get('product')
            product = product.strip()
            product = product.replace(" ", "_")
            product = product.lower()
            print(product)
            version = request.POST.get('version')
            os_actif = request.POST.get('os_actif')
            type_actif = request.POST.get('type_actif')
            importance = request.POST.get('importance')
            print(request.POST.get('id_en'))
            user1 = request.POST.get('id_en')
            user_get = employe.objects.filter(user_id_id=user1)
            entreprise = user_get[0].nom_entreprise_id
            new_cpe = vendor + ":" + product + ":" + version

            try:
                obj = actifs.objects.get(nom_vendor=vendor, nom_actif=product, version_actif=version)
                update_actif = actifs.objects.filter(nom_vendor=vendor, nom_actif=product,
                                                     version_actif=version).update(
                    importance_actif=importance)

            except actifs.DoesNotExist:
                ajouter_actif = actifs.objects.create(nom_vendor=vendor, nom_actif=product, version_actif=version,
                                                      importance_actif=importance, date_ajout_actif=current_date,
                                                      nom_en_id=entreprise, new_cpe_actif=new_cpe)



        else:
            if request.POST.get("form_type") == 'modif_actif':
                vendor = request.POST.get('modif-vendor')
                product = request.POST.get('modif-product')
                version = request.POST.get('modif-version')
                os_actif = request.POST.get('modif-os_actif')
                type_actif = request.POST.get('modif-type_actif')
                importance = request.POST.get('modif-importance')
                new_cpe = (vendor + ":" + product + ":" + version)
                print(request.POST.get('id_modif'))
                actifs.objects.filter(id=request.POST.get('id_modif')).update(version_actif=version,
                                                                              importance_actif=importance,
                                                                              new_cpe_actif=new_cpe)
            else:
                if request.POST.get("form_type") == 'supp_actif':
                    if request.POST.get('reponse') != 'non':
                        cc = request.POST.get('reponse')
                        supp_actif = actifs.objects.get(id=cc).delete()

    get_entre = employe.objects.filter(user_id=current_user.id)
    notifications = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id).order_by('-id_notif')
    count_notif = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, checked=False)

    if request.method == 'GET':
        if request.GET.get('identifiant'):
            identifiant = request.GET.get('identifiant')
            to_update = notif.objects.filter(id_notif=identifiant).update(checked=True)

    context = {
        'data': actif,
        'data2': notifications,
        'count_notif': count_notif,
    }
    return HttpResponse(template.render(context, request))


@login_required(login_url='login')
@allowed_users(allowed_roles=['clients'])
def assets_cve_newtable(request):
    template = loader.get_template('asset_vuln.html')
    current_user = request.user
    actif = actifs.objects.filter(nom_en__employe__user_id_id=current_user.id)
    product1 = product.objects.all()
    liste = []
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    current_date = datetime.datetime.strptime(current_date, "%Y-%m-%d")
    current_date1 = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    w = str(current_date - timedelta(300))
    get_entre = employe.objects.filter(user_id=current_user.id)
    if request.method == 'GET':
        if request.GET.get('cve_no'):
            donnee = request.GET.get('cve_no')
            donnee = donnee.replace(" ", '')
            print('cve', donnee)
            if request.GET.get('cpe_no'):
                cpe_actif = request.GET.get('cpe_no')
                print('cpe', cpe_actif)

                foo_instance = pour_asset.objects.create(cpe=cpe_actif, affected=False, cve_id_id=donnee,
                                                         nom_en_id=get_entre[0].nom_entreprise_id)

    actif_elem = 0
    vuln = ''
    cpe = ''
    if request.method == 'GET':
        if request.GET.get('vuln1'):
            vuln = request.GET.get('vuln1')
            vuln = vuln.replace(" ", '')
            print(type(vuln))
        if request.GET.get('cpe1'):
            cpe = request.GET.get('cpe1')
            print(cpe)
            print(type(cpe))
        if request.GET.get('actif1'):
            actif_elem = int(request.GET.get('actif1'))
            print(actif_elem)
            print(type(actif_elem))
            get_entre = employe.objects.filter(user_id=current_user.id)
        if vuln and cpe and actif_elem:
            if (workflow.objects.filter(cve_id_id=vuln, id_actif_id=actif_elem,
                                        nom_en_id=get_entre[0].nom_entreprise_id).exists()):
                print('exosye')
            else:
                to_insert = workflow.objects.create(nom_en_id=get_entre[0].nom_entreprise_id, id_actif_id=actif_elem,
                                                    cve_id_id=vuln, colonne=1, date_ajout=current_date1)
    actif_products.objects.all().delete()
    variable = ''
    for act in actif:
        result = pour_asset.objects.filter(nom_en__employe__user_id_id=current_user.id)
        asset = product.objects.filter(product=act.nom_actif, vendor=act.nom_vendor, version=act.version_actif,
                                       cve_id__date_modification__gte=w).exclude(cve_id__pour_asset__in=result,
                                                                                 cve_id__pour_asset__affected='False')
        print(asset)
        for prod in asset:
            to_insert = actif_products.objects.create(cpe=prod.cpe, id_actif_client_id=act.id, cve_id=prod.cve_id)

    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        to_update = notif.objects.filter(id_notif=identifiant).update(checked=True)

    asset_vulnerables = actif_products.objects.all()
    nbr_vuln = len(asset_vulnerables)
    print(nbr_vuln)
    not_affected = pour_asset.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, cve_id__date_modification__gte=w)
    nbr_not_aff = len(not_affected)
    notifications = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id).order_by('-id_notif')
    count_notif = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, checked=False)
    label = ["Vulnérabilités qui affectent vos actifs", "Vulnérabilités qui n'affectent pas vos actifs"]
    nbrs =[nbr_vuln, nbr_not_aff]
    total = nbr_vuln+nbr_not_aff
    context = {
        'data': asset_vulnerables,
        'data2': notifications,
        'count_notif': count_notif,
        'labels': label,
        'nbrs': nbrs,
        'total':total,

    }
    return HttpResponse(template.render(context, request))


@login_required(login_url='login')
@allowed_users(allowed_roles=['clients'])
def client(request):
    cves = cve.objects.all().values().order_by('-date_publication')
    page = request.GET.get('page', 1)
    paginator = Paginator(cves, 20)
    page_obj = paginator.get_page(page)
    page_range = paginator.get_elided_page_range(number=page)

    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        print('client', identifiant)
        to_update = notif.objects.filter(id_notif=identifiant).update(checked=True)

    current_user = request.user
    get_entre = employe.objects.filter(user_id=current_user.id)
    notifications = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id).order_by('-id_notif')
    count_notif = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, checked=False)

    context = {
        'page_range': page_range, 'page': page, 'paginator': paginator, 'page_obj': page_obj,
        'data2': notifications,
        'count_notif': count_notif,
    }
    return render(request, 'client.html', context)


def recherche_filtre(request):
    data = request.GET['search']
    filtres = request.GET['filtre']

    if data != '':
        if (filtres == 'CVE' or filtres == ""):
            cvee = cve.objects.filter(cve_id=data).order_by('-date_publication')

        if (filtres == 'Vendor'):
            cvee = product.objects.filter(vendor=data)

        if (filtres == 'Product'):
            cvee = product.objects.filter(product=data)

        if (filtres == 'cwe'):
            cvee = cve_cwe.objects.filter(cwe_id_id=data)

        if (filtres == 'cvss2_score'):
            cvee = cve.objects.filter(cvss2_score=data).order_by('-date_publication')

        if (filtres == 'cvss3_score'):
            cvee = cve.objects.filter(cvss3_score=data).order_by('-date_publication')
    else:
        cvee = cve.objects.all().values().order_by('-date_publication')

    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        print('search', identifiant)
        to_update = notif.objects.filter(id_notif=identifiant).update(checked=True)

    page = request.GET.get('page', 1)
    paginator = Paginator(cvee, 20)
    page_obj = paginator.get_page(page)
    page_range = paginator.get_elided_page_range(number=page)

    current_user = request.user
    get_entre = employe.objects.filter(user_id=current_user.id)
    notifications = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id).order_by('-id_notif')
    count_notif = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, checked=False)

    return render(request, 'recherche_client.html', {'page_range': page_range, 'page': page, 'paginator': paginator,
                                                     'page_obj': page_obj, 'filtre': filtres, 'data2': notifications,
                                                     'count_notif': count_notif,
                                                     })


@login_required(login_url='login')
def une_cve(request, cve_id):
    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        print('cve', identifiant)
        to_update = notif.objects.filter(id_notif=identifiant).update(checked=True)

    cves = cve.objects.filter(cve_id=cve_id).values().order_by('-date_publication')
    prod = product.objects.filter(cve_id_id=cve_id)
    ref = reference.objects.filter(cve_id_id=cve_id)
    cwecve = cve_cwe.objects.filter(cve_id_id=cve_id)
    template = loader.get_template('une_cve.html')

    current_user = request.user
    get_entre = employe.objects.filter(user_id=current_user.id)
    notifications = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id).order_by('-id_notif')
    count_notif = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, checked=False)

    context = {
        'emp': cve_id,
        'cve': cves,
        'cwe': cwecve,
        'prod': prod,
        'ref': ref,
        'cwe': cwecve,
        'data2': notifications,
        'count_notif': count_notif,
    }
    return HttpResponse(template.render(context, request))


@login_required(login_url='login')
@allowed_users(allowed_roles=['clients'])
def une_cve_affected(request, cve_id, actif_aff):
    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        print('affected', identifiant)
        to_update = notif.objects.filter(id_notif=identifiant).update(checked=True)

    cves = cve.objects.filter(cve_id=cve_id).values().order_by('-date_publication')
    prod = product.objects.filter(cve_id_id=cve_id)
    ref = reference.objects.filter(cve_id_id=cve_id)
    cwecve = cve_cwe.objects.filter(cve_id_id=cve_id)
    template = loader.get_template('une_cve_affected.html')

    current_user = request.user
    get_entre = employe.objects.filter(user_id=current_user.id)
    notifications = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id).order_by('-id_notif')
    count_notif = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, checked=False)

    context = {
        'emp': cve_id,
        'cve': cves,
        'cwe': cwecve,
        'prod': prod,
        'ref': ref,
        'cwe': cwecve,
        'data2': notifications,
        'actif_aff': actif_aff,
        'count_notif': count_notif,
    }
    return HttpResponse(template.render(context, request))


def download_pdf(request, cve_id, actif_affected):
    cves = cve.objects.filter(cve_id=cve_id).values()
    ref = reference.objects.filter(cve_id=cve_id).values()
    actif = actifs.objects.get(id=actif_affected)
    template_path = 'pdf.html'
    context = {'data': cves, 'ref': ref, 'actif_affec': actif}
    # Create a Django response object, and specify content_type as pdf
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="Rapport_{}.pdf"'.format(cve_id)
    # find the template and render it.
    template = get_template(template_path)
    html = template.render(context)

    # create a pdf
    pisa_status = pisa.CreatePDF(html, dest=response)
    # if error then show some funny view
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    return response


@unauthenticated_user
def loginPage(request):
    get_mail = ''
    if request.method == 'POST':
        try:
            email_login = request.POST['email'].lower()
            get_mail = User.objects.get(email=email_login)
            print(get_mail)
        except:
            return render(request, 'registration/login.html', {'error': 'Username or password is incorrect!'})
        user = authenticate(username=get_mail, password=request.POST['password'])
        if user is not None:
            if user.groups.filter(name='admins'):
                login(request, user)
                return redirect('/dashboard/')
            else:
                if user.groups.filter(name='clients'):
                    login(request, user)
                    return redirect('client')
                else:
                    if user.groups.filter(name='visiteurs'):
                        login(request, user)
                        return redirect('client')
                    else:
                        return render(request, 'registration/login.html',
                                      {'error': 'Email ou mot de passe incorrect! '})
        else:

            return render(request, 'registration/login.html', {'error': 'Email ou mot de passe incorrect!'})
    else:
        return render(request, 'registration/login.html')


@login_required(login_url='login')
def log_out(request):
    logout(request)
    return redirect('login')


@unauthenticated_user
def signup(request):
    if request.method == "POST":
        if request.POST['password'] == request.POST['confirm_password']:
            nom_user = (request.POST['nom']).lower()
            prenom_user = (request.POST['prenom']).lower()
            entreprise_user = (request.POST['nom_entreprise']).lower()
            email_user = (request.POST['email']).lower()
            try:
                User.objects.get(username=nom_user + '.' + prenom_user)
                return render(request, 'accounts/signup.html', {'error': 'Cet utilisateur existe déja'})
            except User.DoesNotExist:
                try:
                    entre = entreprise.objects.get(nom_en=entreprise_user)
                    try:
                        email_employé = employe.objects.get(email=email_user)
                        return render(request, 'accounts/signup.html', {'error': 'Cet email  est déjà utilisé '})
                    except employe.DoesNotExist:
                        user = User.objects.create_user(username=(nom_user + '.' + prenom_user),
                                                        first_name=prenom_user, last_name=nom_user,
                                                        email=email_user, password=request.POST['password'])
                        getUser = User.objects.filter(username=user)
                        print(getUser[0].id)
                        current_date = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

                        client = employe.objects.create(email=email_user, nom=nom_user,
                                                        prenom=prenom_user, num_tel=request.POST['num_tlfn'],
                                                        job_title=request.POST['job_title'], date_ajout_em=current_date,
                                                        nom_entreprise_id=entre.nom_en, user_id_id=getUser[0].id)
                        group = Group.objects.get(name='visiteurs')
                        user.groups.add(group)

                        return redirect('client')
                    print(entre, 'entreprise existe deja ')
                    print(entre.nom_en)

                except entreprise.DoesNotExist:
                    current_date = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                    create_ent = entreprise.objects.create(nom_en=entreprise_user,
                                                           secteur_activité_en=request.POST['secteur_act'],
                                                           url_en=request.POST['url'], date_ajout_en=current_date)
                    try:
                        email_employé = employe.objects.get(email=email_user)
                        return render(request, 'accounts/signup.html', {'error': 'cet mail  est déjà utilisé '})
                    except employe.DoesNotExist:
                        user = User.objects.create_user(username=(nom_user + '.' + prenom_user),
                                                        first_name=prenom_user, last_name=nom_user,
                                                        email=email_user, password=request.POST['password'])
                        getUser = User.objects.filter(username=user)
                        print(getUser[0].id)
                        current_date = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                        client = employe.objects.create(email=email_user, nom=nom_user,
                                                        prenom=prenom_user, num_tel=request.POST['num_tlfn'],
                                                        job_title=request.POST['job_title'],
                                                        date_ajout_em=current_date,
                                                        nom_entreprise_id=create_ent.nom_en, user_id_id=getUser[0].id)
                        group = Group.objects.get(name='visiteurs')
                        user.groups.add(group)
                        return redirect('client')
                    print(create_ent.nom_en)
                    return redirect('client')
        else:
            return render(request, 'accounts/signup.html', {'error': 'Veuillez vérifier votre mot de passe  '})
    else:
        return render(request, 'accounts/signup.html')


def filtrer_par_date(request):
    template = loader.get_template('hello.html')
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    current_date = datetime.datetime.strptime(current_date, "%Y-%m-%d")
    w = str(current_date - timedelta(366))
    print('hello', w)
    print(current_date)
    print(timedelta(366))

    cves = cve.objects.filter(date_publication__gte=w)

    context = {
        'data': cves,
        # 'data' : w,

    }
    return HttpResponse(template.render(context, request))


@login_required(login_url='login')
@allowed_users(allowed_roles=['clients'])
def workflowPage(request):
    template = loader.get_template('workflow.html')

    current_user = request.user
    actif = actifs.objects.filter(nom_en__employe__user_id_id=current_user.id)
    current_date1 = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    get_entre = employe.objects.filter(user_id=current_user.id)

    actif_elem = 0
    vuln = ''
    cpe = ''
    if request.method == 'GET':
        if request.GET.get('vuln1'):
            vuln = request.GET.get('vuln1')
            vuln = vuln.replace(" ", '')
            print(type(vuln))
        if request.GET.get('cpe1'):
            cpe = request.GET.get('cpe1')
            print(cpe)
            print(type(cpe))
        if request.GET.get('actif1'):
            actif_elem = int(request.GET.get('actif1'))
            print(actif_elem)
            print(type(actif_elem))
            get_entre = employe.objects.filter(user_id=current_user.id)
        if vuln and cpe and actif_elem:
            if (workflow.objects.filter(cve_id_id=vuln, id_actif_id=actif_elem,
                                        nom_en_id=get_entre[0].nom_entreprise_id).exists()):
                print('exosye')
            else:
                to_insert = workflow.objects.create(nom_en_id=get_entre[0].nom_entreprise_id, id_actif_id=actif_elem,
                                                    cve_id_id=vuln, colonne=1, date_ajout=current_date1)

    if request.method == 'GET':
        if request.GET.get('vuln2'):
            vuln = request.GET.get('vuln2')
            vuln = vuln.replace(" ", '')
        if request.GET.get('actif2'):
            actif_elem = int(request.GET.get('actif2'))
            get_entre = employe.objects.filter(user_id=current_user.id)
        if vuln and actif_elem:
            if (workflow.objects.filter(cve_id_id=vuln, id_actif_id=actif_elem,
                                        nom_en_id=get_entre[0].nom_entreprise_id).exists()):
                print('zxiste')
            else:
                to_insert = workflow.objects.create(nom_en_id=get_entre[0].nom_entreprise_id, id_actif_id=actif_elem,
                                                    cve_id_id=vuln, colonne=1, date_ajout=current_date1)
                print("insert")

    card1 = workflow.objects.filter(colonne=1)
    card2 = workflow.objects.filter(colonne=2)

    card3 = workflow.objects.filter(colonne=3)
    card4 = workflow.objects.filter(colonne=4)

    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        print('workflow', identifiant)
        to_update = notif.objects.filter(id_notif=identifiant).update(checked=True)

    cart = 0
    colomn = 0
    if request.method == 'GET':
        if request.GET.get('post_id'):
            cart = int(request.GET.get('post_id'))
            print('cart ', cart)

        if request.GET.get('colonne'):
            colomn = int(request.GET.get('colonne'))
            print('je suis chez liste: ', colomn)

        workflow.objects.filter(id_cart=cart).update(colonne=colomn)

        notifications = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id).order_by('-id_notif')
        count_notif = notif.objects.filter(nom_en_id=get_entre[0].nom_entreprise_id, checked=False)

    context = {
        'card1': card1,
        'card2': card2,
        'card3': card3,
        'card4': card4,
        'id': cart,
        'data2': notifications,
        'test': test,
        'count_notif': count_notif,

    }
    return HttpResponse(template.render(context, request))


@login_required(login_url='login')
@admin_only
def dashboard_admin(request):
    template = loader.get_template('dashboard-admin.html')
    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        to_update = notification_admin.objects.filter(id_notif_admin=identifiant).update(checked=True)

    if request.method == 'POST':
        response = request.POST.get('validite')
        email = request.POST.get('user')
        id_user = request.POST.get('id_user')
        print(id_user)
        current_date = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        if response == "Valider":
            to_valide_compte = employe.objects.filter(email=email).update(valide=True, date_modif_statut=current_date)
            group_remove = Group.objects.get(name='visiteurs')
            group_add = Group.objects.get(name='clients')
            group_add.user_set.add(id_user)
            group_remove.user_set.remove(id_user)
        else:
            to_valide_compte = employe.objects.filter(email=email).update(valide=False, date_modif_statut=current_date)
            group_remove = Group.objects.get(name='clients')
            group_add = Group.objects.get(name='visiteurs')
            group_add.user_set.add(id_user)
            group_remove.user_set.remove(id_user)

    users_visiteurs = User.objects.filter(groups__name='visiteurs')
    liste_visiteurs = []

    for j in users_visiteurs:
        # print(j.id)
        test = employe.objects.filter(user_id_id=j.id)
        liste_visiteurs.append(test)

    notifications_admin = notification_admin.objects.all().order_by('-id_notif_admin')
    count_notif_admin = notification_admin.objects.filter(checked=False)

    context = {
        'data': users_visiteurs,
        'all_visiteurs': liste_visiteurs,
        'notifications_admin': notifications_admin,
        'count': count_notif_admin,

    }
    return HttpResponse(template.render(context, request))


@login_required(login_url='login')
@admin_only
def dashboard_gere_client(request):
    template = loader.get_template('dashboard-gerer-client.html')

    if request.method == 'POST':
        response = request.POST.get('validite')
        email = request.POST.get('user')
        id_user = request.POST.get('id_client')
        print(id_user)
        current_date = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        if response == "Valider":
            to_valide_compte = employe.objects.filter(email=email).update(valide=True, date_modif_statut=current_date)
            group_remove = Group.objects.get(name='visiteurs')
            group_add = Group.objects.get(name='clients')
            group_add.user_set.add(id_user)
            group_remove.user_set.remove(id_user)

        else:
            to_valide_compte = employe.objects.filter(email=email).update(valide=False, date_modif_statut=current_date)
            group_remove = Group.objects.get(name='clients')
            group_add = Group.objects.get(name='visiteurs')
            group_add.user_set.add(id_user)
            group_remove.user_set.remove(id_user)

    users_clients = User.objects.filter(groups__name='clients')
    liste_clients = []

    for j in users_clients:
        # print(j.id)
        test = employe.objects.filter(user_id_id=j.id)
        liste_clients.append(test)

    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        to_update = notification_admin.objects.filter(id_notif_admin=identifiant).update(checked=True)

    notifications_admin = notification_admin.objects.all().order_by('-id_notif_admin')
    count_notif_admin = notification_admin.objects.filter(checked=False)

    context = {
        'data': users_clients,
        'all_clients': liste_clients,
        'notifications_admin': notifications_admin,
        'count': count_notif_admin,

    }
    return HttpResponse(template.render(context, request))


@login_required(login_url='login')
@admin_only
def dashboard_entreprises(request):
    template = loader.get_template('dashboard-entreprises.html')
    entreprises = entreprise.objects.all().order_by('-date_ajout_en')
    liste_entreprise_employe = []

    for j in entreprises:
        test = employe.objects.filter(nom_entreprise_id=j.nom_en).order_by('-date_ajout_em')
        liste_entreprise_employe.append(test)
        print(liste_entreprise_employe)

    if request.method == 'GET':
        identifiant = request.GET.get('identifiant')
        to_update = notification_admin.objects.filter(id_notif_admin=identifiant).update(checked=True)

    notifications_admin = notification_admin.objects.all().order_by('-id_notif_admin')
    count_notif_admin = notification_admin.objects.filter(checked=False)
    count_entreprise = employe.objects.all().distinct('nom_entreprise_id')

    count_users = employe.objects.all()
    count_users_visiteurs = employe.objects.filter(valide='')

    context = {
        'all_employ': liste_entreprise_employe,
        'notifications_admin': notifications_admin,
        'count': count_notif_admin,
        'count_entreprise': count_entreprise,
        'count_users': count_users,
        'count_users_visiteurs': count_users_visiteurs,

    }
    return HttpResponse(template.render(context, request))


def page_presentative(request):
    return render(request, 'page_presentative.html', {})


def explorer(request):
    cves = cve.objects.all().values().order_by('-date_publication')
    page = request.GET.get('page', 1)
    paginator = Paginator(cves, 20)
    page_obj = paginator.get_page(page)
    page_range = paginator.get_elided_page_range(number=page)

    context = {
        'page_range': page_range, 'page': page, 'paginator': paginator, 'page_obj': page_obj,

    }
    return render(request, 'explorer.html', context)


def non_autorise(request):
    context = {
    }
    return render(request, 'non_autorisé.html', context)


def explorer_cve(request, cve_id):
    cves = cve.objects.filter(cve_id=cve_id).values().order_by('-date_publication')
    prod = product.objects.filter(cve_id_id=cve_id)
    ref = reference.objects.filter(cve_id_id=cve_id)
    cwecve = cve_cwe.objects.filter(cve_id_id=cve_id)
    context = {
        'emp': cve_id,
        'cve': cves,
        'cwe': cwecve,
        'prod': prod,
        'ref': ref,
        'cwe': cwecve,
    }
    return render(request, 'explorer_cve.html', context)


def explorer_recherche(request):
    if request.POST['search'] != "":
        data = request.POST['search']
        filtres = request.POST['filtre']
        if data != '':
            if (filtres == 'CVE' or filtres == ''):
                cvee = cve.objects.filter(cve_id=data).order_by('-date_publication')
        else:
            cvee = cve.objects.all().values().order_by('-date_publication')
    else:
        cvee = cve.objects.all().values().order_by('-date_publication')

    context = {
        'page_obj': cvee,
    }
    return render(request, 'explorer_recherche.html', context)


def download_exe(request):
    file_name = 'main.exe'
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path_to_file = open(BASE_DIR + '/CVE_BD/' + file_name, 'rb')
    response = HttpResponse(path_to_file.read(), content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename="AppVersionScan.exe"'
    return response


class UserActifView(APIView):
    def post(self, request):
        serializerall = UserActifSerializer(data=request.data)
        nom_ent = employe.objects.filter(email=request.data['user']['email'])

        for actif in request.data['actif']:
            actif.update({'nom_en': nom_ent[0].nom_entreprise_id})
            actif.update({'date_ajout_actif': datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")})
        if serializerall.is_valid():
            print('saru', request.data)
            serializeractif = ActifSerializer(instance='', data=request.data['actif'], many=True)
            print(request.data['actif'])
            if serializeractif.is_valid():
                serializeractif.save()
                return Response({"status": "success"}, status=status.HTTP_200_OK)
        else:
            return Response({"status": "error", 'data': serializerall.errors}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        serializer = UserDataSerializer(data=request.data)
        if serializer.is_valid():
            test = User.objects.filter(email=request.data['email'])
            user = authenticate(username=test[0].username, password=request.data['password'])
            if user:
                return Response({"status": "sucess"}, status=status.HTTP_200_OK)
            else:
                return Response({" Compte inexistant, veuillez vous inscrire sur notre plateforme"},
                                status=status.HTTP_400_BAD_REQUEST)

