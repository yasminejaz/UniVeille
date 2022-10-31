from datetime import datetime

from rest_framework import serializers
from rest_framework.relations import PrimaryKeyRelatedField

from .models import actifs, entreprise
from django.contrib.auth.models import User


class UserDataSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields =['email','password']



class ActifListSerializer(serializers.ListSerializer):
    def update(self, instance, validated_data):
        ret = []
        for data in validated_data:
            nom_entreprise = data['entreprise']
            nom = nom_entreprise['nom_en']
            actif = actifs.objects.filter(new_cpe_actif=data['new_cpe_actif'], nom_en_id=data['entreprise']['nom_en'])
            if actif:
                actifs.objects.filter(new_cpe_actif=data['new_cpe_actif'], nom_en_id=data['entreprise']['nom_en']).update(nom_vendor=data['nom_vendor'], nom_actif= data['nom_actif'], new_cpe_actif=data['new_cpe_actif'],date_ajout_actif=data['date_ajout_actif']
                                                                                                            ,version_actif=data['version_actif'], importance_actif=data['importance_actif'],nom_en_id=data['entreprise']['nom_en'])
                ret.append(data)
            else:
                ret.append(actifs.objects.create(nom_vendor=data['nom_vendor'], nom_actif= data['nom_actif'], new_cpe_actif=data['new_cpe_actif'],
                                                 version_actif=data['version_actif'],date_ajout_actif=data['date_ajout_actif'],
                                                importance_actif=data['importance_actif'],nom_en_id=data['entreprise']['nom_en']))
        return ret


class ActifSerializer(serializers.ModelSerializer):
    nom_vendor = serializers.CharField()
    nom_actif = serializers.CharField()
    version_actif = serializers.CharField()
    new_cpe_actif = serializers.CharField(required=True)
    nom_en= serializers.CharField(source='entreprise.nom_en')
    date_ajout_actif = serializers.CharField(required=False)
    importance_actif = serializers.CharField(required=True)

    class Meta:
        model = actifs
        fields = ['nom_vendor', 'nom_actif', 'version_actif', 'new_cpe_actif','date_ajout_actif', 'importance_actif', 'nom_en']
        list_serializer_class = ActifListSerializer


class UserActifSerializer(serializers.ModelSerializer):
    user = UserDataSerializer(many=False)
    actif = ActifSerializer(many=True)

    class Meta:
        model = actifs
        fields = ['user', 'actif']
