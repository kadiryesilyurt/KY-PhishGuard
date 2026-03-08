import requests
import time
import sys

API_KEY = "SENIN_API_ANAHTARIN_BURAYA_GELECEK"

def linki_tara(url):
    print("\n" + "=" * 60)
    print(f"[*] HEDEF LİNK ANALİZ EDİLİYOR: {url}")
    print("=" * 60)

    tarama_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-apikey": API_KEY, "content-type": "application/x-www-form-urlencoded"}
    
    response = requests.post(tarama_url, data={"url": url}, headers=headers)
    if response.status_code != 200:
        return print(f"[!] Hata: Sunucuya ulaşılamadı. Kod: {response.status_code}")

    analiz_id = response.json()['data']['id']
    rapor_url = f"https://www.virustotal.com/api/v3/analyses/{analiz_id}"
    headers_get = {"accept": "application/json", "x-apikey": API_KEY}

    animasyon = ["|", "/", "-", "\\"]
    idx = 0

    while True:
        rapor_data = requests.get(rapor_url, headers=headers_get).json()
        if rapor_data['data']['attributes']['status'] == "completed":
            sys.stdout.write("\r[+] Tarama %100 tamamlandı! Sonuçlar getiriliyor...        \n")
            sys.stdout.flush()
            break
        sys.stdout.write(f"\r[*] Analiz devam ediyor, motorlar devrede... {animasyon[idx % len(animasyon)]}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.5) 
            
    stats = rapor_data['data']['attributes']['stats']
    zararli, supheli, temiz = stats['malicious'], stats['suspicious'], stats['harmless']

    print("=" * 60 + f"\n🚨 RAPOR -> Zararlı: {zararli} | Şüpheli: {supheli} | Temiz: {temiz}\n" + "=" * 60)

    if zararli > 0 or supheli > 0:
        print("\n[!] TESPİT EDİLEN TEHDİT DETAYLARI:")
        for motor, detay in rapor_data['data']['attributes']['results'].items():
            if detay.get('category') in ['malicious', 'suspicious']:
                print(f"   ➤ {motor:<15} : {detay.get('result').upper()}")
        print("\n[!!!] KRİTİK UYARI: BU LİNK BİR OLTALAMA VEYA ZARARLI SİTEDİR!")
    else:
        print("\n[+] Sistem tehdit algılamadı. Yeni sitelere dikkat edin.")

if __name__ == "__main__":
    if len(sys.argv) == 2: linki_tara(sys.argv[1])
    else: print("Kullanım: python phishing_analyzer.py <hedef_link>")