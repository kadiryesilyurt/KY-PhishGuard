import requests
import time
import sys
import whois
from urllib.parse import urlparse
from datetime import datetime

# Renk Kodları (Terminali pavyona çeviren ama profesyonel gösteren kısım)
KIRMIZI = '\033[91m'
SARI = '\033[93m'
YESIL = '\033[92m'
MAVI = '\033[96m'
KALIN = '\033[1m'
SIFIRLA = '\033[0m'

API_KEY = "SENIN_API_ANAHTARIN_BURAYA_GELECEK"

def alan_adi_cikar(url):
    parsed = urlparse(url if "//" in url else f"http://{url}")
    domain = parsed.netloc
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def whois_sorgula(domain):
    print(f"\n{MAVI}[*] 1. AŞAMA: Alan Adı (WHOIS) İstihbaratı Toplanıyor...{SIFIRLA}")
    try:
        w = whois.whois(domain)
        kurulus_tarihi = w.creation_date
        
        if type(kurulus_tarihi) is list:
            kurulus_tarihi = kurulus_tarihi[0]
            
        if kurulus_tarihi:
            yas = (datetime.now() - kurulus_tarihi).days
            print(f"[+] Domain: {domain}")
            print(f"[+] Kuruluş Tarihi: {kurulus_tarihi.strftime('%Y-%m-%d')}")
            
            if yas < 30:
                print(f"\n{KIRMIZI}{KALIN}[!] DİKKAT: Bu site henüz sadece {yas} günlük!{SIFIRLA}")
                print(f"{KIRMIZI}[!] Orijinal kurum adresi olmayabilir veya yepyeni bir site olabilir.{SIFIRLA}")
                print(f"{KIRMIZI}[!] Güvenliğiniz için emin olmadan bu linke tıklamamanız tavsiye edilir.{SIFIRLA}")
            elif yas < 180:
                print(f"\n{SARI}[!] BİLGİ: Bu site {yas} günlük (6 aydan daha yeni). Dikkatli işlem yapın.{SIFIRLA}")
            else:
                print(f"\n{YESIL}[+] BİLGİ: Bu site {yas} gündür aktif. (Uzun süredir kullanımda){SIFIRLA}")
        else:
            print("[-] WHOIS kaydında kuruluş tarihi bulunamadı (Gizlenmiş olabilir).")
            
    except Exception as e:
        print("[-] WHOIS sorgusu yapılamadı veya geçersiz alan adı.")

def linki_tara(url):
    print("\n" + "=" * 60)
    print(f"{KALIN}[*] HEDEF ANALİZİ BAŞLATILDI: {url}{SIFIRLA}")
    print("=" * 60)

    domain = alan_adi_cikar(url)
    whois_sorgula(domain)

    print(f"\n{MAVI}[*] 2. AŞAMA: VirusTotal Derinlemesine Tarama Başlıyor...{SIFIRLA}")
    tarama_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"accept": "application/json", "x-apikey": API_KEY, "content-type": "application/x-www-form-urlencoded"}
    
    response = requests.post(tarama_url, data={"url": url}, headers=headers)
    if response.status_code != 200:
        return print(f"{KIRMIZI}[!] Hata: Sunucuya ulaşılamadı. Kod: {response.status_code}{SIFIRLA}")

    analiz_id = response.json()['data']['id']
    rapor_url = f"https://www.virustotal.com/api/v3/analyses/{analiz_id}"
    headers_get = {"accept": "application/json", "x-apikey": API_KEY}

    animasyon = ["|", "/", "-", "\\"]
    idx = 0

    while True:
        rapor_data = requests.get(rapor_url, headers=headers_get).json()
        if rapor_data['data']['attributes']['status'] == "completed":
            sys.stdout.write(f"\r{YESIL}[+] Tarama %100 tamamlandı! Sonuçlar getiriliyor...        {SIFIRLA}\n")
            sys.stdout.flush()
            break
        sys.stdout.write(f"\r[*] Antivirüs motorları devrede... {animasyon[idx % len(animasyon)]}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.5) 
            
    stats = rapor_data['data']['attributes']['stats']
    zararli, supheli, temiz = stats['malicious'], stats['suspicious'], stats['harmless']

    print("=" * 60)
    print(f"🚨 RAPOR -> {KIRMIZI}Zararlı: {zararli}{SIFIRLA} | {SARI}Şüpheli: {supheli}{SIFIRLA} | {YESIL}Temiz: {temiz}{SIFIRLA}")
    print("=" * 60)

    if zararli > 0 or supheli > 0:
        print(f"\n{KALIN}[!] TESPİT EDİLEN TEHDİT DETAYLARI:{SIFIRLA}")
        for motor, detay in rapor_data['data']['attributes']['results'].items():
            kategori = detay.get('category')
            if kategori in ['malicious', 'suspicious']:
                # Zararlıyı kırmızı, şüpheliyi sarı yapıyoruz
                renk = KIRMIZI if kategori == 'malicious' else SARI
                print(f"   ➤ {MAVI}{motor:<15}{SIFIRLA} : {renk}{detay.get('result').upper()}{SIFIRLA}")
        
        print(f"\n{KIRMIZI}{KALIN}🚨 🚨 [!!!] SONUÇ: VT Motorları bu linkte zararlı içerik tespit etti! 🚨 🚨{SIFIRLA}")
    else:
        print(f"\n{YESIL}[+] VT motorları tehdit algılamadı. (Eğer site yeniyse manuel kontrole devam edin).{SIFIRLA}")

if __name__ == "__main__":
    if len(sys.argv) == 2: linki_tara(sys.argv[1])
    else: print("Kullanım: python phishing_analyzer.py <hedef_link>")