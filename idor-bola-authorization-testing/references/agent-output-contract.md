# 109. Sonuç

IDOR/BOLA araştırmasının temel formülü:

```text
                 OBJECT AUTHORIZATION

Authenticated A
       +
Object owned by B
       +
Protected operation
       ↓
Should be denied
```

Gerçek bulgu:

```text
A token
   +
B object
   ↓
B's private data / resource / action
```

En değerli araştırma alanları:

```text
JSON nested objects
GraphQL nested resolvers/mutations
multiple IDs
parent-child resources
owner/object mismatch
tenant/object mismatch
custom headers
cookies
file/download/export endpoints
UUID/opaque references
microservices
gateway/downstream mismatches
alternate API versions
HTTP method differences
WebSocket messages
canonicalization/encoding mismatches
JWT identity/authorization boundaries
```

**Temel prensip:** Encoding, UUID, hash, Base64, JWT, nonce veya opaque ID kullanılması
authorization sağlamaz. Güvenliği belirleyen şey server'ın authenticated identity ile
hedef object'in ownership/tenant ilişkisini doğru şekilde doğrulamasıdır.

## Agent output contract

Bir bulgu (veya bulgu adayı) raporlanırken, agent'ın çıktısı — ister bir
kullanıcıya sunulan metin, ister başka bir aracın/pipeline'ın tüketeceği
yapılandırılmış veri olsun — aşağıdaki alanları içermelidir. Bu format
bölüm 31 (authorization matrix), bölüm 37 (kanıt standardı + confidence
score) ve bölüm 38 (severity) bölümlerinde anlatılanların tek bir çıktı
şablonunda birleşimidir:

```text
STATUS:
  SAFE / CANDIDATE / CONFIRMED / NOT_TESTABLE

CLASS:
  IDOR              → doğrudan object-level authorization bypass
  BOLA              → API bağlamındaki modern karşılığı (aynı kök,
                       farklı isimlendirme — bkz. bölüm 0)
  BFLA              → function/endpoint-level (object değil, aksiyonun
                       kendisi yetkisiz)
  AUTH_BYPASS       → authentication zafiyeti (JWT/session/token —
                       bkz. bölüm 28 "authentication bypass ile IDOR'u
                       ayır")
  GATEWAY_MISMATCH  → microservice/proxy katmanları arası ayrışma
                       (bölüm 18)
  CACHE_LEAK        → paylaşılan cache kaynaklı sızıntı (bölüm 49)
  RACE_CONDITION    → TOCTOU/eşzamanlılık (bölüm 48)
  PARSER_DIFF       → encoding/content-type/normalization farkı
                       (bölüm 15-17, 63-67)
  WAF_BYPASS        → WAF/CDN atlatma sonrası ortaya çıkan IDOR
                       (bölüm 105-108 — bypass bir ÖNCÜLdür, asıl
                       bulgu genelde yukarıdaki sınıflardan biridir)
  CORS_CHAIN        → CORS misconfiguration + IDOR zinciri (bölüm 81)
  INFO_LEAK         → object existence/ownership sızıntısı, tam erişim
                       değil (bölüm 44 blind IDOR, bölüm 69 GraphQL
                       error leakage)

  Bu liste kök nedeni (WAF_BYPASS gibi) tespit mekanizmasından (asıl
  IDOR/BOLA bulgusundan) ayırmak içindir; bir bulgu birden fazla CLASS
  etiketi taşıyabilir (ör. "WAF_BYPASS → IDOR").

ACTOR:
  <authenticated identity — A>

OBJECT:
  <hedeflenen object referansı — B'nin object'i>

OWNER:
  <response'tan çıkarılan gerçek owner — bölüm 37 ownership evidence>

TENANT:
  <varsa tenant/organization/workspace>

EXPECTED:
  DENY  (bölüm 31 authorization matrix'e göre)

OBSERVED:
  ALLOW / DENY
  (PARTIAL_LEAK durumları için bkz. bölüm 37a "OBSERVED/CLASS eşlemesi")

METHOD:
  <GET/POST/PUT/PATCH/DELETE vb.>

ENDPOINT:
  <path/URL>

REFERENCE_SOURCE:
  <object reference nereden bulundu — bölüm 50 "Object Reference
  Acquisition" kategorilerinden biri>

EVIDENCE:
  <bölüm 37'deki dört-parçalı kanıt + ilgili response alanları>

IMPACT:
  <bölüm 38 severity çerçevesine göre kısa değerlendirme>

CONFIDENCE:
  0-5  (bölüm 37 confidence score tablosuna göre)
```

Bu şablonun asıl amacı, `CONFIDENCE < 3` olan hiçbir sonucun "bulgu"
olarak sunulmamasını garanti altına almaktır — böylece "200 aldım, IDOR
buldum" tarzı erken/zayıf sonuçlar yapısal olarak elenir. `STATUS:
CANDIDATE` ve altındaki sonuçlar, kullanıcıya "doğrulanmamış, insan
teyidi gerekir" notuyla birlikte sunulmalıdır; yalnızca `CONFIRMED`
(confidence 5) sonuçlar kesin bulgu dilinde raporlanabilir.

## Güvenlik sınırı

Bu skill yalnızca açıkça yetkilendirilmiş bug bounty programları, pentest
ortamları, CTF'ler veya kullanıcının sahip olduğu sistemler için kullanılmalıdır.

Agent; rate limitleri aşmamalı, üçüncü taraf hesaplarına erişmeye çalışmamalı,
gerçek kullanıcı verisi toplamamalı ve kapsam dışı varlıklarda test yapmamalıdır.

JWT `alg:none`, algorithm confusion veya signature-validation konularında
uygulamanın doğrulama davranışını güvenli şekilde doğrulayabilir; gerçek
hedeflerde sahte/admin token üretme veya authentication bypass için operasyonel
istismar talimatları uygulamamalıdır.
