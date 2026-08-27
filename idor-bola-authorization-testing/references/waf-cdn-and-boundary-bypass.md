# 78. Request Smuggling ile Object-Level Authorization Bypass

HTTP Request Smuggling (CL.TE, TE.CL, TE.TE) ile:

```http
POST /api/orders/1001 HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
0

GET /api/orders/1002 HTTP/1.1
Host: target.com
```

Front-end `1001` ile authorize ederken back-end `1002` ile işlem yapabilir. Bu, bölüm 18'deki gateway/service mismatch'in request smuggling varyasyonudur.

---

# 79. DNS Rebinding ile Internal API'lere Erişim

Bazı durumlarda internal microservice'ler doğrudan erişilebilir değildir ama DNS rebinding ile:

```text
attacker.com → 1.2.3.4 (public IP)
attacker.com → 10.0.0.5 (internal IP, TTL düşük)
```

Internal API'lere erişilip object-level authorization test edilebilir.

---

# 81. CORS Misconfiguration ile Cross-Origin Object Access

```http
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

veya:

```http
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

CORS misconfiguration varsa, victim'in browser'ından attacker'in sitesine authenticated request yapılarak object-level authorization test edilebilir. Bu, IDOR'u tarayıcı tabanlı exploit edilebilir hale getirir.

---

# 104. Referer / Origin Header'ına Dayalı Access-Control Bypass

Bazı uygulamalar bir endpoint'in yalnızca kendi frontend'inden çağrıldığını
(ve dolayısıyla "güvenli" olduğunu) `Referer` veya `Origin` header'ına
bakarak varsayar:

```http
GET /api/internal/users/1002/export
Referer: https://app.example.com/dashboard
```

Bu header'lar tamamen client-controlled olduğundan trivially spoof
edilebilir:

```http
GET /api/internal/users/1002/export
Referer: https://app.example.com/dashboard
Origin: https://app.example.com
```

Eğer bir endpoint'in tek koruması bu header'ların varlığı/değeriyse (gerçek
authentication/authorization kontrolü değil), bu hem CSRF hem de
object-level authorization açısından değerlendirilmelidir: `Referer`/
`Origin` doğru gönderildiğinde `A token + B object` testi (bkz. bölüm 8)
hâlâ geçiyorsa, header kontrolü authorization'ın yerini tutmuyor demektir
ve asıl object-level kontrolün var olup olmadığı ayrıca doğrulanmalıdır.
Bu, bölüm 81'deki CORS misconfiguration'dan farklıdır — CORS tarayıcı
davranışıyla ilgiliyken buradaki sorun sunucunun bu header'lara
"authentication kanıtı" gibi güvenmesidir.

---

# 105. Host Header / Virtual-Host Bypass

Bazı mimarilerde 403/401 kararı, load balancer/reverse proxy/vhost
yönlendirmesinden **önceki** bir katmanda değil, `Host` header'ına göre
seçilen backend/vhost içinde verilir. `Host` header'ı tamamen
client-controlled olduğundan, farklı değerlerle denenmesi kısıtlanmamış
bir internal vhost'a veya farklı bir routing kararına düşülmesini
sağlayabilir:

```http
GET /admin/users/1002 HTTP/1.1
Host: app.example.com          → 403

GET /admin/users/1002 HTTP/1.1
Host: localhost                → ?

GET /admin/users/1002 HTTP/1.1
Host: 127.0.0.1                → ?

GET /admin/users/1002 HTTP/1.1
Host: internal.example.com     → ?

GET /admin/users/1002 HTTP/1.1
Host: app.example.com.attacker.com   → ?

GET /admin/users/1002 HTTP/1.1
Host: app.example.com:80@attacker.com → ?
```

Test edilmesi gereken varyantlar:

```text
1. localhost / 127.0.0.1 / 0.0.0.0 / internal hostname'ler
2. Bilinen internal/staging subdomain'ler (admin., internal., staging.,
   dev., api-internal. vb. — recon aşamasında subdomain enumeration'dan
   elde edilenler)
3. Host header'ının port eklenmiş hâli (app.example.com:8080)
4. Birden fazla Host header gönderme (bazı parser'lar ilkini, bazıları
   sonuncusunu okur — bkz. bölüm 47 "HTTP Parameter Pollution" ile aynı
   kök neden, burada header seviyesinde)
5. X-Forwarded-Host ile Host header'ının çelişmesi
```

Bu teknik yalnızca `403 → farklı Host → 200` sonucu **gerçekten korunan
kaynağın içeriğini/aksiyonunu** döndürdüğünde bulgu olarak değerlendirilir
(bkz. bölüm 37 kanıt standardı); yalnızca status code değişimi tek başına
yeterli değildir.

---

# 106. WAF / CDN Atlayıp Doğrudan Origin Sunucuya Erişim

Dosyadaki path/header/encoding tabanlı bypass teknikleri (bölüm 61, 65-67,
67a-67b) uygulama/proxy katmanında çalışır. Ancak birçok gerçek dünya 403'ü
aslında **CDN/WAF seviyesinde** (Cloudflare, Akamai, Imperva vb.) uygulanır
— bu durumda uygulama katmanındaki hiçbir trick işe yaramaz, çünkü istek
hiç origin sunucuya ulaşmadan WAF'ta engellenir. Bu senaryoda en yüksek
etkili teknik, **origin sunucunun gerçek IP adresini bulup WAF'ı tamamen
atlayarak doğrudan ona bağlanmaktır**:

```text
1. Origin IP keşfi (yalnızca kapsam dahilindeyse ve pasif/OSINT
   yöntemlerle):
   - DNS geçmişi (SecurityTrails, ViewDNS, DNSDumpster gibi pasif
     kayıt servisleri)
   - SSL/TLS sertifika şeffaflık logları (crt.sh) — aynı sertifikayı
     kullanan diğer subdomain/IP'ler
   - Eski/unutulmuş subdomain'ler (ör. direct.example.com, origin.,
     ftp., mail., cpanel.) WAF'ın arkasında değil doğrudan origin'e
     çözümleniyor olabilir
   - Shodan/Censys gibi servislerde sunucu banner'ı, sertifika ortak
     adı (CN/SAN) üzerinden eşleştirme
   - E-posta header'larından sızan sunucu IP'si (ör. şifre sıfırlama
     e-postası origin sunucudan doğrudan gönderiliyorsa)

2. Doğrulama: bulunan IP'ye doğrudan bağlanıp Host header'ı hedef
   domain olacak şekilde ayarlanır:

   GET / HTTP/1.1
   Host: app.example.com
   (bağlantı doğrudan bulunan-IP:443'e yapılır, DNS çözümlemesi
   CDN'e gitmez)

3. Eğer origin, gelen isteğin gerçekten CDN'den mi geldiğini
   doğrulamıyorsa (ör. bir "sadece CDN IP'lerinden kabul et"
   firewall kuralı veya paylaşılan bir secret header yoksa), WAF
   tamamen devre dışı kalır ve altındaki tüm uygulama, bu skill'deki
   diğer tüm object-level authorization testlerine WAF'sız şekilde
   maruz kalır.
```

Bu teknik yalnızca **açıkça kapsam dahilinde olan, pasif/OSINT yöntemlerle**
uygulanmalıdır; aktif port taraması veya kapsam dışı IP aralıklarına
saldırı bu skill'in güvenlik sınırının dışındadır (bkz. bölüm 109
"Güvenlik sınırı").

**"Pasif" tanımı:** Burada "pasif", hedef sunucuya (origin veya CDN)
doğrudan tarama/prob amaçlı istek atılmaması anlamına gelir — port
taraması, dizin brute-force'u veya IP aralığı taraması yapılmaz.
DNS geçmişi servisleri, sertifika şeffaflık logları veya arama motorları
gibi **üçüncü taraf kaynaklara** sorgu atmak bu tanım kapsamında pasif
sayılır (bu kaynaklar zaten herkese açık, önceden toplanmış veriyi
sunar). Adım 2'deki tek bir doğrulama isteği (origin IP'ye tek bir
`GET /` isteği) hedefin kapsam dahilinde olduğu doğrulandıktan sonra
kabul edilebilir bir aktif adımdır — ama bunun ötesinde origin IP'ye
karşı herhangi bir tarama/fuzzing yapılmamalıdır.

---

# 107. WAF Fail-Open / Malformed Request ile Evasion

Bazı WAF/reverse-proxy implementasyonları, işleyemediği (parse edemediği,
zaman aşımına uğrayan veya kaynak limitini aşan) bir isteği **incelemeden
backend'e geçirir** (fail-open davranışı) ya da farklı şekilde parse eder:

```text
1. Aşırı büyük header/body: WAF belirli bir boyuttan sonra
   incelemeyi durdurup isteği olduğu gibi iletebilir.
2. Çok sayıda header: WAF header sayısı/toplam boyutu limitine
   takılıp isteği tam parse edemeyebilir.
3. Chunked transfer encoding garipliği veya bozuk
   Content-Length/Transfer-Encoding kombinasyonu: WAF ile backend'in
   isteği farklı sınırlarda ayırması (bu, bölüm 78 "Request Smuggling"
   ile aynı kök nedendir, ancak buradaki amaç smuggling değil WAF'ın
   kural eşleştirmesini bozmaktır).
4. WAF'ın desteklemediği/parse edemediği bir Content-Type veya
   charset ile payload'ı "görünmez" hâle getirme.
5. HTTP/2 ile HTTP/1.1 arasında farklı header normalizasyonu
   (bazı WAF'lar yalnızca HTTP/1.1 kurallarını uygular).
```

Bu teknikler klasik bir "kısıtlanan path'e eriş" testinden çok, WAF'ın
kural motorunu atlatıp arkasındaki object-level authorization
kontrolüne (varsa) çıplak şekilde ulaşmayı amaçlar. Sonuç yine bölüm 37'deki
kanıt standardına göre doğrulanmalıdır: WAF atlatıldığını göstermek tek
başına bulgu değildir, arkasındaki uygulamanın gerçekten korumasız bir
object/action'a eriştiğini göstermek gerekir.

---

# 108. Static-File Handler Üzerinden Auth Middleware Atlatma

Bazı framework'lerde static dosya sunucusu (nginx `location`, Express
`static()`, Spring `ResourceHandler` vb.) route tanımlarında authorization
middleware'inden **önce** eşleşir. Bir path'in sonuna statik bir dosya
uzantısı veya segmenti eklemek, isteği auth middleware'i olmayan bu
handler'a düşürebilir:

```text
/admin/users/1002              → 403 (auth middleware devrede)
/admin/users/1002.js           → ?
/admin/users/1002.json         → ?
/admin/users/1002/nonexistent.css → ?
/admin/users/1002/..%2f..%2fadmin/users/1002.png → ?
/static/../admin/users/1002
```

Mantık: statik dosya handler'ı "bu bir dosya isteği" diye path'i farklı
yorumlayıp doğrudan dosya sistemine/başka bir route'a yönlendirebilir; bu
route auth middleware zincirinde değilse, aynı endpoint'e middleware'siz
bir yoldan ulaşılmış olur. Bu, bölüm 20 ("Alternate endpoint / API
version") ve bölüm 66 ("Trailing Slash / Path Normalization") ile aynı
kök nedeni paylaşır — farklı bir route/handler, farklı bir authorization
zinciri.

---
