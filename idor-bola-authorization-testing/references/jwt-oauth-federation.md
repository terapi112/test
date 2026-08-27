# 23. JWT ve authorization

JWT:

```text
HEADER.PAYLOAD.SIGNATURE
```

Örneğin:

```json
{
  "sub": "123",
  "role": "user",
  "nonce": "8f7a..."
}
```

IDOR açısından genellikle:

```text
sub
user_id
uid
account_id
tenant_id
```

gibi identity claim'ler daha önemlidir.

`nonce` tek başına IDOR değildir. Nonce çoğunlukla auth-flow/replay bağlamında
kullanılır.

## Nonce / jti / state kavramlarının ayrımı

"Nonce" tek bir kavram değildir — bağlama göre farklı amaçlara hizmet eden
en az altı farklı mekanizma aynı isimle anılır. Agent bunları birbirine
karıştırmamalıdır, çünkü her biri farklı bir güvenlik özelliğini bağlar:

```text
JWT "nonce" claim'i
  → genellikle OIDC id_token içinde bulunur, authorization request ile
    token'ı eşleştirir (replay/injection önleme). Object-level
    authorization ile DOĞRUDAN ilgisi yoktur.

OIDC nonce (authorization request parametresi)
  → client'ın ürettiği, id_token'a geri yansıyan değer; **token binding**
    değil, **request-response binding** sağlar (authorization code
    injection saldırılarını önler).

OAuth "state" parametresi
  → CSRF önleme amaçlıdır; authorization flow'unun başlatan client ile
    callback'i alan client'ın aynı olduğunu doğrular. Identity binding
    değildir.

JWT "jti" (JWT ID) claim'i
  → token'ın kendisini tekil olarak tanımlar; **replay prevention**
    (aynı token'ın tekrar kullanılmasını engelleme — genellikle bir
    blocklist/allowlist ile) için kullanılır. Identity claim'i değildir.

Session identifier (session cookie/token)
  → **identity binding** sağlar: hangi kullanıcının oturum açtığını
    belirler. IDOR testinde asıl önemli olan budur (sub/user_id ile
    birlikte).

Anti-replay nonce (bazı API imzalama şemalarında)
  → her isteğin tekil olmasını sağlar (aynı isteğin tekrar
    gönderilmesini engeller); **authorization binding** değil, **request
    integrity/replay prevention** sağlar.
```

Özetle dört farklı güvenlik özelliği vardır ve bunlar birbirinin yerine
geçmez:

```text
identity binding        → session identifier, JWT sub/user_id claim'i
token binding            → OIDC nonce (request ↔ token eşleşmesi)
replay prevention        → jti, anti-replay nonce
authorization binding    → hiçbiri tek başına değil — asıl backend'in
                            her request'te "bu identity gerçekten bu
                            object'e erişebilir mi?" kontrolünü yapması
```

Bir JWT'de `nonce` veya `jti` claim'inin bulunması, backend'in
object-level authorization kontrolü yaptığı anlamına gelmez — bunlar
farklı bir tehdit modelini (replay, injection, CSRF) hedefler. Agent bir
JWT'de bu alanları gördüğünde "authorization burada sağlanıyor" diye
varsaymamalı, yine de bölüm 8'deki temel A/B object testini uygulamalıdır.

Doğru test mantığı:

```text
JWT A
  ↓
sub=A
  ↓
A object → 200
B object → 403/404
```

Eğer:

```text
JWT A
  ↓
B object
  ↓
B private data
```

dönüyorsa JWT'yi değiştirmeden de BOLA doğrulanabilir.

---

# 24. JWT signature doğrulama davranışı

JWT'nin imzasını doğrulamak authentication'ın temel parçalarındandır.

Geçerli token:

```text
valid signature → authenticated
```

Geçersiz token:

```text
invalid signature → reject
```

Signature yoksa:

```text
missing signature → reject
```

beklenir.

Yetkili testlerde davranış matrisi:

```text
valid token              → expected success
invalid signature        → expected 401
missing signature        → expected 401
expired token             → expected 401
valid token + victim obj → expected 403/404
```

şeklinde tutulabilir.

---

# 25. JWT algorithm configuration

JWT header'ında örneğin:

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

bulunabilir.

Güvenli uygulama beklenen algoritmayı server-side policy ile belirlemelidir.

Tarihsel olarak yanlış veya güvensiz implementasyonlarda:

```text
alg: none
algorithm confusion
algorithm selection based solely on untrusted header
```

gibi sorunlar görülmüştür.

Özellikle `alg:none` konusu tarihsel bir JWT doğrulama zafiyeti sınıfıdır.

Güvenli davranış:

```text
client-supplied alg
       ↓
expected algorithm policy ile karşılaştır
       ↓
mismatch → reject
```

olmalıdır.

Bu skill gerçek hedefte sahte/admin JWT üretme, signature bypass etme veya
algoritma doğrulamasını istismar edecek operasyonel token üretim adımları
sağlamaz. Bunun yerine uygulamanın **geçersiz token karşısındaki davranışı**
test edilir.

---

# 26. JWT algorithm confusion

RS256 gibi asymmetric ve HS256 gibi symmetric algoritmalar farklı güvenlik
modellerine sahiptir.

Riskli tasarım:

```text
JWT alg
  ↓
server hangi verifier'ı kullanacağını client tokenından seçiyor
```

Güvenli tasarım:

```text
endpoint/config
  ↓
expected algorithm = RS256
  ↓
JWT alg == RS256 ?
  ↓
signature verification
```

Agent, algorithm mismatch durumunda beklenen `401/invalid token` davranışını
doğrulamalıdır.

---

# 27. "Signature'ı silince kabul ediliyor" testi

Yetkili testte amaç admin token üretmek değil, validation davranışını gözlemlemektir.

Karşılaştır:

```text
valid JWT
invalid-signature JWT
missing-signature JWT
expired JWT
```

Beklenen:

```text
valid → authenticated
invalid → rejected
missing → rejected
expired → rejected
```

Eğer geçersiz/missing signature protected resource'a erişim sağlıyorsa
authentication/JWT verification problemi vardır.

Bu, IDOR'dan ayrı bir bulgu olabilir.

---

# 28. Authentication bypass ile IDOR'u ayır

Örnek:

```text
Invalid JWT
   +
victim object
   ↓
200 + private data
```

Bu öncelikle authentication/JWT validation problemidir.

Diğer tarafta:

```text
Valid attacker JWT
   +
victim object
   ↓
200 + private data
```

Bu BOLA/IDOR'dur.

İki problemi birbirine karıştırma.

---

# 42. Güvenli JWT test özeti

JWT için agent:

```text
valid JWT
invalid signature
missing signature
expired JWT
wrong/mismatched algorithm
```

davranışlarını gözlemleyebilir.

Beklenen:

```text
valid → authenticate
invalid → reject
missing → reject
expired → reject
algorithm mismatch → reject
```

JWT manipulation'ın amacı IDOR testi ise önce JWT'yi değiştirmeden:

```text
valid A token + B object
```

test edilmelidir.

Authentication bypass ile BOLA birbirinden ayrı raporlanmalıdır.

---

# 74. OAuth / OpenID Connect ID Token Manipülasyonu

OAuth akışında ID token içindeki claim'ler:

```json
{
  "sub": "111",
  "email": "a@example.com",
  "user_id": "111"
}
```

Eğer uygulama ID token'daki `sub` yerine client-controlled bir parametreyi kullanıyorsa:

```http
POST /api/callback
id_token=TOKEN&user_id=222
```

object-level authorization bypass oluşabilir. Ayrıca `nonce`, `state`, `redirect_uri` manipülasyonları da değerlendirilmelidir.

---

# 75. SAML Assertion Manipülasyonu

SAML response içindeki NameID ve attribute değerleri:

```xml
<saml:NameID>user_a@example.com</saml:NameID>
<saml:Attribute Name="user_id">
  <saml:AttributeValue>111</saml:AttributeValue>
</saml:Attribute>
```

Signature bypass veya assertion wrapping ile bu değerler değiştirilebilirse, object-level authorization etkilenebilir.

---

# 80. Open Redirect ile OAuth Token Çalma ve Sonrasında IDOR

Open redirect zafiyeti ile:

```text
https://target.com/oauth/callback?code=AUTH_CODE&redirect_uri=https://evil.com
```

Authorization code çalınıp victim'in hesabına erişim sağlandıktan sonra, bu token ile victim'in object'lerine erişilebilir. Bu IDOR'un ön koşulu olan authentication bypass'tır.

---
