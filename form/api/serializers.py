from rest_framework.serializers import ModelSerializer
from form.models import  Participant,Coordinator


class ParticipantSerializer(ModelSerializer):
    class Meta:
        model = Participant
        fields = '__all__'