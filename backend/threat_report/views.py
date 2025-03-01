from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt
def fetch_links(request):
    if request.method == 'GET':
        # Simulate fetching JSON data from the frontend
        json_data = request.GET.get('data')
        if json_data:
            links = json.loads(json_data)
            print("Fetched Links:", links)
            return JsonResponse({'status': 'success', 'links': links})
        else:
            return JsonResponse({'status': 'error', 'message': 'No data provided'}, status=400)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            print("Received Links:", data)
            return JsonResponse({'status': 'success', 'message': 'Data received successfully'})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)