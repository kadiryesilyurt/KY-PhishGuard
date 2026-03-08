import requests
import time
import sys

API_KEY = "SENIN_API_ANAHTARIN_BURAYA_GELECEK"

def linki_tara(url):
    print(f"[*] HEDEF LİNK ANALİZ EDİLİYOR: {url}")
    tarama_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-apikey": API_KEY, "content-type": "application/x-www-form-urlencoded"}
    response = requests.post(tarama_url, data={"url": url}, headers=headers)

    analiz_id = response.json()['data']['id']
    rapor_url = f"https://www.virustotal.com/api/v3/analyses/{analiz_id}"
    headers_get = {"accept": "application/json", "x-apikey": API_KEY}

    while True:
        rapor_data = requests.get(rapor_url, headers=headers_get).json()
        if rapor_data['data']['attributes']['status'] == "completed":
            print("[+] Tarama tamamlandı!\n")
            break
        print("[-] Rapor bekleniyor, 5 saniye uyutuluyor...")
        time.sleep(5)
            
    stats = rapor_data['data']['attributes']['stats']
    print(f"🔴 Zararlı: {stats['malicious']} | 🟠 Şüpheli: {stats['suspicious']} | 🟢 Temiz: {stats['harmless']}")

if __name__ == "__main__":
    if len(sys.argv) == 2: linki_tara(sys.argv[1])