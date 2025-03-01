from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from urllib.parse import urlparse
from .models import TrustedLink
import requests
import base64

VIRUSTOTAL_API_KEY = '1b4f20f47f2d02987b1e5dcfbb666f87ce3cde6cc8b419033353fe05d26664da'  # Replace with your VirusTotal API key

@csrf_exempt
def fetch_links(request):
    if request.method == 'GET':
        # Simulate fetching JSON data from the frontend
        json_data = request.GET.get('data')
        if json_data:
            links = json.loads(json_data)
            # print("Fetched Links:", links)
            return JsonResponse({'status': 'success', 'links': links})
        else:
            return JsonResponse({'status': 'error', 'message': 'No data provided'}, status=400)
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            print("Received Links:", data)
            trusted_links = [link.url for link in TrustedLink.objects.all()]
            results = []
            checked_domains = set()

            for item in data:
                link = item.get('link')
                if link and link != 'No direct link':
                    domain = urlparse(link).netloc
                    if domain in trusted_links:
                        results.append({'link': link, 'status': 'trusted'})
                    elif domain not in checked_domains:
                        # Check the link with VirusTotal
                        vt_response = check_with_virustotal(link)
                        checked_domains.add(domain)
                        if vt_response:
                            results.append({'link': link, 'status': 'untrusted', 'virustotal': vt_response})
                        else:
                            results.append({'link': link, 'status': 'untrusted', 'virustotal': 'error'})
                    else:
                        results.append({'link': link, 'status': 'untrusted', 'virustotal': 'already checked'})
                else:
                    results.append({'link': link, 'status': 'no direct link'})

            # print(results)
            return JsonResponse({'status': 'success', 'results': results})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

def check_with_virustotal(link):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    print(link)
    # try:
    #     # Encode the URL in base64 format as required by VirusTotal API
    # #    encoded_url = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
    #     print(f"Checking link with VirusTotal: {link}")
    #     response = requests.get(f"{url}/{encoded_url}", headers=headers)
    #     if response.status_code == 200:
    #         print(response.json())
    #         return response.json()
    #     else:
    #         return None
    # except Exception as e:
    #     print(f"Error checking with VirusTotal: {e}")
    #     return None