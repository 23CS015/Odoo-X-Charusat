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
    if request.method == 'POST':
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

            output = process_results(safe_links, virustotal_responses)
            return JsonResponse({'status': 'success', 'results': output})
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

@csrf_exempt
def check_link(request):
    url = request.GET.get("url", "").strip()

    if not url:
        return JsonResponse({"status": "error", "message": "No URL provided"}, status=400)

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if TrustedLink.objects.filter(url=domain).exists():
        return JsonResponse({
            "status": "success",
            "URL": url,
            "threat_level": "Safe",
            "Malicious Count": 0,
            "Harmless Count": 1,
            "Undetected Count": 0,
            "User Votes Malicious": 0,
            "User Votes Harmless": 1,
            "Reputation Score": 100
        })

    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(api_url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if "data" not in data or "attributes" not in data["data"]:
            return JsonResponse({"status": "error", "message": "No analysis data found"}, status=404)

        attributes = data["data"]["attributes"]
        stats = attributes["last_analysis_stats"]

        threat_level = "Safe"
        if stats["malicious"] > 0:
            threat_level = "Malicious"
        elif stats["undetected"] > 0:
            threat_level = "Undetected"

        return JsonResponse({
            "status": "success",
            "URL": url,
            "threat_level": threat_level,
            "Malicious Count": stats["malicious"],
            "Harmless Count": stats["harmless"],
            "Undetected Count": stats["undetected"],
            "User Votes Malicious": attributes["total_votes"].get("malicious", 0),
            "User Votes Harmless": attributes["total_votes"].get("harmless", 0),
            "Reputation Score": attributes.get("reputation", 0)
        })

    except requests.exceptions.RequestException as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)

def check_with_virustotal(link):
    url = "https://www.virustotal.com/api/v3/urls/"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        encoded_url = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
        response = requests.get(f"{url}{encoded_url}", headers=headers)
        response.raise_for_status()
        analysis_data = response.json()

        if "data" not in analysis_data or "attributes" not in analysis_data["data"]:
            return None

        return analysis_data
    except requests.exceptions.RequestException:
        return None
    except json.JSONDecodeError:
        return None
    except KeyError:
        return None
    except Exception:
        return None

def process_results(safe_links, virustotal_responses):
    safe = []
    undetected = []
    malicious = []

    for link in safe_links:
        safe.append({
            "URL": link,
            "Malicious Count": 0,
            "Harmless Count": 1,
            "Undetected Count": 0,
            "User Votes Malicious": 0,
            "User Votes Harmless": 1,
            "Reputation Score": 100
        })

    for response in virustotal_responses:
        attributes = response["data"]["attributes"]
        link = attributes["url"]
        malicious_count = attributes["last_analysis_stats"]["malicious"]
        harmless_count = attributes["last_analysis_stats"]["harmless"]
        undetected_count = attributes["last_analysis_stats"]["undetected"]
        user_votes_malicious = attributes["total_votes"].get("malicious", 0)
        user_votes_harmless = attributes["total_votes"].get("harmless", 0)
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
        elif undetected_count > 0:
            undetected.append(link_info)
        else:
            safe.append(link_info)

    summary = {
        "Total Links": len(safe) + len(undetected) + len(malicious),
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
