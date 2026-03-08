# KY-PhishGuard
# 🎣 KY-PhishGuard | Akıllı Oltalama (Phishing) Analiz Aracı

**KY-PhishGuard**, şüpheli bağlantıları (URL) 70'ten fazla global antivirüs motorunda aynı anda tarayan ve **WHOIS verileriyle** sitenin yaşını hesaplayarak saniyeler içinde tehdit istihbaratı sunan Python tabanlı gelişmiş bir güvenlik aracıdır.

Gerçek dünyadaki oltalama (SMS Phishing) saldırılarına karşı hızlı bir doğrulama mekanizması kurmak; aynı zamanda siber güvenlikte **Tehdit İstihbaratı (Threat Intelligence) servislerinin ve RESTful API mimarilerinin nasıl çalıştığını deneyimlemek** amacıyla geliştirilmiştir.

## 🚀 Öne Çıkan Özellikler
* **Alan Adı İstihbaratı (WHOIS):** Hedef sitenin ne zaman kurulduğunu tespit eder. Dolandırıcıların sık kullandığı "taze (1-2 günlük)" siteleri anında ifşa eder.
* **Çoklu Motor Taraması:** Kaspersky, BitDefender, Fortinet gibi devlerin veritabanını aynı anda sorgular.
* **Akıllı Bekleme (Polling):** API'nin analiz süresini dinamik olarak takip eder, boşuna zaman kaybettirmez.
* **Tehdit Detaylandırması:** Sadece "Zararlı" demez, tespit edilen tehdidin türünü (Malware, Phishing, Trojan vb.) ekrana basar.
* **Dinamik Renkli Arayüz:** Terminali spamlemez, tehlike seviyesine göre (Kırmızı/Sarı/Yeşil) ANSI renk kodlarıyla uyarı veren görsel bir rapor sunar.

## 🛠️ Kurulum ve Kullanım

Script, API ile iletişim kurmak ve alan adı sorgulamak için `requests` ve `python-whois` kütüphanelerine ihtiyaç duyar.

```bash
# Gerekli kütüphaneleri kurun:
pip install requests python-whois

# Aracı çalıştırın:
python phishing_analyzer.py <supheli-link>

# Örnek:
python phishing_analyzer.py [https://garanti-bbva-mobil.com](https://garanti-bbva-mobil.com)
```

🔑 Kendi API Anahtarınızı (API Key) Nasıl Alırsınız?
Bu aracı kendi bilgisayarınızda çalıştırmak için ücretsiz bir VirusTotal API anahtarına ihtiyacınız vardır:

VirusTotal Community adresine gidin ve ücretsiz kayıt olun.

Sağ üst köşedeki profil isminize tıklayın ve "API key" sekmesini seçin.

Ekranda yazan alfanumerik kodu kopyalayın.

phishing_analyzer.py dosyasını bir metin editörüyle açıp, en üstteki API_KEY = "SENIN_API_ANAHTARIN_BURAYA_GELECEK" kısmına kendi anahtarınızı yapıştırın.

⚠️ Uyarı: Bu araç dakikada 4, günde 500 sorgu limiti olan standart Public API kullanmaktadır. Oltalama analizi ve güvenlik araştırmaları (OSINT) için eğitim/savunma amaçlı yazılmıştır.
