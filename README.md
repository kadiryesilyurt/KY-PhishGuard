# KY-PhishGuard
# 🎣 KY-PhishGuard | Akıllı Oltalama (Phishing) Analiz Aracı

**KY-PhishGuard**, şüpheli bağlantıları (URL) 70'ten fazla global antivirüs motorunda aynı anda tarayarak saniyeler içinde tehdit istihbaratı sunan Python tabanlı bir güvenlik aracıdır.

Gerçek dünyadaki oltalama (SMS Phishing) saldırılarına karşı hızlı bir doğrulama mekanizması kurmak; aynı zamanda siber güvenlikte **Tehdit İstihbaratı (Threat Intelligence) servislerinin ve RESTful API mimarilerinin nasıl çalıştığını deneyimlemek** amacıyla geliştirilmiştir.

## 🚀 Öne Çıkan Özellikler
* **Çoklu Motor Taraması:** Kaspersky, BitDefender, Fortinet gibi devlerin veritabanını aynı anda sorgular.
* **Akıllı Bekleme (Polling):** API'nin analiz süresini dinamik olarak takip eder, boşuna zaman kaybettirmez.
* **Tehdit Detaylandırması:** Sadece "Zararlı" demez, tespit edilen tehdidin türünü (Malware, Phishing, Trojan vb.) ekrana basar.
* **Akıcı Arayüz:** Terminali spamlemez, asenkron görünümlü yükleme (spinner) animasyonu kullanır.

## 🛠️ Kurulum ve Kullanım

Script, API ile iletişim kurmak için `requests` kütüphanesine ihtiyaç duyar.

```bash
# Gerekli kütüphaneyi kurun:
pip install requests

# Aracı çalıştırın:
python phishing_analyzer.py <supheli-link>

# Örnek:
python phishing_analyzer.py [https://garanti-bbva-mobil.com](https://garanti-bbva-mobil.com)

```

## 🔑 Kendi API Anahtarınızı (API Key) Nasıl Alırsınız?

Bu aracı kendi bilgisayarınızda çalıştırmak için ücretsiz bir VirusTotal API anahtarına ihtiyacınız vardır:

1. [VirusTotal Community](https://www.virustotal.com/) adresine gidin ve ücretsiz kayıt olun.
2. Sağ üst köşedeki profil isminize tıklayın ve **"API key"** sekmesini seçin.
3. Ekranda yazan alfanumerik kodu kopyalayın.
4. `phishing_analyzer.py` dosyasını bir metin editörüyle açıp, en üstteki `API_KEY = "SENIN_API_ANAHTARIN_BURAYA_GELECEK"` kısmına kendi anahtarınızı yapıştırın.

---

⚠️ **Uyarı:** Bu araç dakikada 4, günde 500 sorgu limiti olan standart Public API kullanmaktadır. Oltalama analizi ve güvenlik araştırmaları (OSINT) için eğitim/savunma amaçlı yazılmıştır.
