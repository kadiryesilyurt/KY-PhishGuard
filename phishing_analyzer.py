import requests
import time
import sys

API_KEY = "SENIN_API_ANAHTARIN_BURAYA_GELECEK"

def linki_tara(url):
    print(f"[*] Analiz Başlatılıyor: {url}")
    tarama_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-apikey": API_KEY, "content-type": "application/x-www-form-urlencoded"}
    payload = {"url": url}

    response = requests.post(tarama_url, data=payload, headers=headers)
    if response.status_code != 200:
        return print("[!] API Bağlantı Hatası!")

    analiz_id = response.json()['data']['id']
    print("[*] 10 saniye bekleniyor...")
    time.sleep(10)
    
    rapor_url = f"https://www.virustotal.com/api/v3/analyses/{analiz_id}"
    rapor_response = requests.get(rapor_url, headers={"accept": "application/json", "x-apikey": API_KEY})
    stats = rapor_response.json()['data']['attributes']['stats']

    print(f"Zararlı: {stats['malicious']} | Şüpheli: {stats['suspicious']} | Temiz: {stats['harmless']}")

if __name__ == "__main__":
    if len(sys.argv) == 2: linki_tara(sys.argv[1])