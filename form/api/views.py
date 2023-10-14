from rest_framework.decorators import api_view
from rest_framework.response import Response
from form.models import Participant,Coordinator
from .serializers import ParticipantSerializer
from form.api import serializers


@api_view(['GET'])
def getRoutes(request):
    routes = [
        'GET /api/',
        'GET /api/participants',
        'GET /api/participant/<int:key>'
    ]
    return Response(routes)


@api_view(['GET'])
def getParticipants(request):
    participants = Participant.objects.all()
    serializer = ParticipantSerializer(participants, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def getParticipants_withid(request,pk):
    participants = Participant.objects.get(id=pk)
    serializer = ParticipantSerializer(participants, many=True)
    return Response(serializer.data)