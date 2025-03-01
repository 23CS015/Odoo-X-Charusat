from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from urllib.parse import urlparse
from .models import TrustedLink
import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv('VT_API_KEY')

VIRUSTOTAL_API_KEY = api_key  # Replace with your VirusTotal API key

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
            safe_links = []
            virustotal_responses = []

            for item in data:
                link = item.get('link')
                if link and link != 'No direct link':
                    domain = urlparse(link).netloc
                    if domain in trusted_links:
                        safe_links.append(link)
                        results.append({'link': link, 'status': 'trusted'})
                    elif domain not in checked_domains:
                        # Check the link with VirusTotal
                        vt_response = check_with_virustotal(link)
                        checked_domains.add(domain)
                        if vt_response:
                            virustotal_responses.append(vt_response)
                            results.append({'link': link, 'status': 'untrusted', 'virustotal': vt_response})
                        else:
                            results.append({'link': link, 'status': 'untrusted', 'virustotal': 'error'})
                    else:
                        results.append({'link': link, 'status': 'untrusted', 'virustotal': 'already checked'})
                else:
                    results.append({'link': link, 'status': 'no direct link'})

            # Process the results and send to another function
            output = process_results(safe_links, virustotal_responses)
            print("Output:", output)
            # print(results)
            return JsonResponse({'status': 'success', 'results': output})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

def check_with_virustotal(link):
    url = "https://www.virustotal.com/api/v3/urls/"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        # Encode the URL in base64 format as required by VirusTotal API
        encoded_url = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
        print(f"Checking link with VirusTotal: {link}")
        response = requests.get(f"{url}{encoded_url}", headers=headers)
        response.raise_for_status()
        analysis_data = response.json()

        if "data" not in analysis_data or "attributes" not in analysis_data["data"]:
            print(f"Error: Could not retrieve analysis data for {link}")
            return None

        return analysis_data
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"JSON Decode Error: {e}")
        return None
    except KeyError as e:
        print(f"Key Error: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def process_results(safe_links, virustotal_responses):
    safe = []
    undetected = []
    malicious = []

    for link in safe_links:
        safe.append({
            "URL": link,
            "Malicious Count": 0,
            "Harmless Count": 0,
            "Undetected Count": 0,
            "User Votes Malicious": 0,
            "User Votes Harmless": 0,
            "Reputation Score": 0
        })

    for response in virustotal_responses:
        attributes = response["data"]["attributes"]
        link = attributes["url"]
        malicious_count = attributes["last_analysis_stats"]["malicious"]
        harmless_count = attributes["last_analysis_stats"]["harmless"]
        undetected_count = attributes["last_analysis_stats"]["undetected"]
        user_votes_malicious = attributes["total_votes"]["malicious"]
        user_votes_harmless = attributes["total_votes"]["harmless"]
        reputation_score = attributes.get("reputation", 0)

        link_info = {
            "URL": link,
            "Malicious Count": malicious_count,
            "Harmless Count": harmless_count,
            "Undetected Count": undetected_count,
            "User Votes Malicious": user_votes_malicious,
            "User Votes Harmless": user_votes_harmless,
            "Reputation Score": reputation_score
        }

        if malicious_count > 0:
            malicious.append(link_info)
        else:
            safe.append(link_info)

    summary = {
        "Total Links": len(safe_links) + len(virustotal_responses),
        "Safe Count": len(safe),
        "Undetected Count": len(undetected),
        "Malicious Count": len(malicious)
    }

    return {
        "Safe": safe,
        "Undetected": undetected,
        "Malicious": malicious,
        "Summary": summary
    }