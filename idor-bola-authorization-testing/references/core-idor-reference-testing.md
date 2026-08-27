# 1. IDOR nedir?

Uygulama bir object identifier alır:

```http
GET /api/orders/1001
Authorization: Bearer TOKEN_A
```

`1001` A kullanıcısına aitse erişim beklenir.

Aynı token ile:

```http
GET /api/orders/1002
Authorization: Bearer TOKEN_A
```

gönderildiğinde `1002` B kullanıcısına ait olmasına rağmen B'nin özel verisi
dönüyorsa object-level authorization başarısızdır.

Önemli ayrım:

```text
ID değiştirdim → 200 OK
```

tek başına yeterli kanıt değildir.

Şunun gösterilmesi gerekir:

```text
TOKEN_A
   +
OBJECT_B
   ↓
B'nin protected data/resource'u
```

---

# 2. IDOR/BOLA türleri

Resmi ve evrensel bir "IDOR türleri" listesi yoktur; bug bounty açısından
aşağıdaki sınıflandırma kullanılabilir.

## 2.1 Horizontal IDOR

Aynı yetki seviyesindeki başka kullanıcının object'ine erişim:

```text
User A → kendi order'ı       ✓
User A → User B'nin order'ı  ✗
```

## 2.2 Vertical / privilege-related object authorization

Normal kullanıcı, daha yüksek yetki gerektiren object/resource'a erişebiliyorsa:

```text
Normal user
   ↓
/api/admin/users/123
   ↓
admin data
```

Bu durum IDOR/BOLA ile BFLA (Broken Function Level Authorization) arasında
değerlendirilebilir; kesin sınıflandırma endpoint'in davranışına bağlıdır.

## 2.3 Read IDOR

Başka kullanıcının:

- profilini
- siparişini
- faturasını
- mesajını
- dosyasını
- ticket'ını
- raporunu
- adresini

okuyabilme.

## 2.4 Write/Modify IDOR

Başkasının object'ini değiştirme:

```http
PUT /api/profile/222
```

## 2.5 Delete IDOR

Başkasının object/resource'unu silebilme:

```http
DELETE /api/files/222
```

## 2.6 Action IDOR

Object üzerinde action uygulanabilmesi:

```text
/orders/{id}/cancel
/orders/{id}/refund
/files/{id}/download
/users/{id}/export
/messages/{id}/archive
```

## 2.7 File IDOR

Dosya, belge, fotoğraf, attachment, export veya download resource'larında.

## 2.8 API/BOLA

REST, GraphQL veya başka API'lerde object-level authorization'ın eksik olması.

## 2.9 Unauthenticated object access

Authentication olmadan private object'e erişim:

```text
No token
   +
victim object
   ↓
private data
```

Bu klasik authenticated IDOR'dan daha ciddi bir access-control/authentication
problemine dönüşebilir.

---

# 3. En sık görülen object reference alanları

Sadece `id` arama.

## URL path

```text
/users/123
/orders/123
/accounts/123
/customers/123
/files/123
/documents/123
/messages/123
/tickets/123
/projects/123
```

## Query parameters

```text
id
user_id
userid
uid
account_id
customer_id
client_id
member_id
profile_id
order_id
invoice_id
payment_id
transaction_id
document_id
file_id
attachment_id
message_id
ticket_id
project_id
team_id
organization_id
org_id
company_id
address_id
product_id
item_id
post_id
comment_id
conversation_id
chat_id
session_id
request_id
```

Ek olarak sık atlanan parametre isimleri:

```text
tenant_id
workspace_id
group_id
role_id
subscription_id
plan_id
cart_id
wallet_id
card_id
bank_account_id
coupon_id
voucher_id
contract_id
application_id
submission_id
form_id
survey_id
booking_id
reservation_id
appointment_id
employee_id
staff_id
driver_id
vehicle_id
shipment_id
tracking_id
tracking_number
order_number
invoice_number
reference_number
ref_id
correlation_id
external_id
internal_id
legacy_id
short_id
slug
api_key
apikey
access_token
refresh_token
webhook_id
integration_id
connection_id
export_id
import_id
job_id
batch_id
report_id
log_id
event_id
notification_id
alert_id
campaign_id
ad_id
lead_id
deal_id
contact_id
opportunity_id
policy_id
claim_id
case_id
incident_id
ticket_number
account_number
iban
```

Not: `email`, `username`, `phone` gibi alanlar da bazı uygulamalarda doğrudan
lookup anahtarı olarak kullanılır (örn. `GET /api/users?email=victim@x.com`);
bunlar klasik numeric ID olmasa da object reference işlevi görebilir ve aynı
ownership testine tabi tutulmalıdır.

## Generic/semantic names

```text
owner
owner_id
subject
subject_id
resource
resource_id
object
object_id
ref
reference
uuid
guid
key
token
parent
parent_id
child
child_id
target
target_id
source
source_id
requester
requester_id
sender_id
receiver_id
recipient_id
from_id
to_id
approver_id
reviewer_id
assignee_id
creator_id
author_id
publisher_id
editor_id
actor_id
principal_id
```

Bir alanın adı object reference'a benzemiyorsa bile response ve backend
davranışından object ilişkisi anlaşılabilir.

---

# 4. JSON body IDOR

Örnek:

```http
POST /api/invoice/details HTTP/2
Authorization: Bearer TOKEN_A
Content-Type: application/json

{
  "invoice_id": "1001"
}
```

A'nın faturası `1001`, B'nin faturası `1002` ise:

```json
{
  "invoice_id": "1002"
}
```

ve hâlâ `TOKEN_A` kullanıldığında B'nin faturası dönüyorsa BOLA/IDOR vardır.

## Nested JSON

```json
{
  "account": {
    "id": "111"
  },
  "document": {
    "id": "789"
  }
}
```

Hem `account.id` hem `document.id` authorization açısından değerlendirilmelidir.

## Identity/object mismatch

```json
{
  "user_id": "111",
  "document_id": "789"
}
```

Frontend veya gateway `user_id` üzerinden authorization yapıp backend
`document_id` üzerinden object lookup yapıyorsa iki alanın ilişkisi kontrol
edilmiyor olabilir.

Test soruları:

```text
logged-in user == user_id ?
document.owner == logged-in user ?
document belongs to user_id ?
```

---

# 5. Bir request'te birden fazla ID

Bu, gelişmiş IDOR testlerinin en önemli alanlarından biridir.

Örnek:

```json
{
  "requester_id": "111",
  "target_id": "222"
}
```

veya:

```json
{
  "user_id": "111",
  "owner_id": "222",
  "resource_id": "333",
  "tenant_id": "444"
}
```

Her identifier farklı bir entity'yi temsil edebilir.

Şu modeli oluştur:

```text
A = authenticated user
B = target user
C = object owner
D = resource
E = tenant
```

Sonra ilişkileri değerlendir:

```text
A == C ?
C owns D ?
A belongs to E ?
D belongs to E ?
B allowed to access D ?
```

Asıl aranacak hata:

```text
Frontend relationship
        ≠
Backend relationship
```

## Relationship graph modeli

Yukarıdaki A/B/C/D/E harflerini ayrı ayrı değerlendirmek yerine, agent
bunları bir **ilişki grafiği** olarak modellemelidir. Tipik bir hiyerarşi:

```text
                 ┌───────────────┐
                 │ Auth Identity │
                 │       A       │
                 └───────┬───────┘
                         │ belongs_to
                         ▼
                 ┌───────────────┐
                 │    Tenant     │
                 │       T       │
                 └───────┬───────┘
                         │ owns
                         ▼
                 ┌───────────────┐
                 │    Object     │
                 │       O       │
                 └───────┬───────┘
                         │ contains
                         ▼
                 ┌───────────────┐
                 │ Child Object  │
                 │       C       │
                 └───────────────┘
```

Bu grafikten çıkan invariant'lar (her request'te doğru olması beklenen
kurallar):

```text
A owns O           (ya da: A member_of owner(O))
O belongs_to T
C belongs_to O
A belongs_to T
```

Bir `A token + O_B` (A'nın token'ı, B'ye ait bir object) isteği geldiğinde
agent şu iki soruyu sırayla değerlendirmelidir:

```text
1. A == owner(O_B) ?             → hayırsa IDOR adayı
2. A belongs_to tenant(O_B) ?    → hayırsa cross-tenant IDOR adayı
```

Bu model özellikle nested/child object'lerde (`C belongs_to O`) faydalıdır:
`C`'ye erişim genellikle `O`'nun sahipliği üzerinden devralınır, ama
backend bunu `C`'nin kendi ID'sinden bağımsız olarak kontrol ediyorsa
(`GET /orders/{O}/items/{C}` isteğinde yalnızca `C`'nin var olup olmadığı
kontrol edilip `C`'nin gerçekten `O`'ya ait olup olmadığı kontrol
edilmiyorsa), bu bölüm 6'daki "Parent ID + child ID" pattern'inin nested
resource varyasyonuna denk gelir.

---

# 6. Parent ID + child ID

Örnek:

```http
GET /api/users/111/orders/222
```

Burada:

```text
111 = user
222 = order
```

Doğru authorization:

```text
order 222 owner == user 111
AND
user 111 == authenticated user
```

Hatalı backend yalnızca:

```sql
SELECT * FROM orders WHERE id = 222
```

gibi object lookup yapıyorsa parent path'teki user ID güvenlik kontrolü
için kullanılmıyor olabilir.

Bu durum özellikle:

```text
/users/{user}/orders/{order}
/accounts/{account}/files/{file}
/projects/{project}/documents/{document}
/organizations/{org}/members/{member}
```

gibi nested endpoint'lerde araştırılmalıdır.

---

# 7. Owner ID + Object ID mismatch

Örneğin:

```json
{
  "id": "222",
  "owner_id": "111"
}
```

Uygulama `owner_id` ile authorization yapıp `id` ile object lookup yapıyorsa,
iki alanın gerçekten aynı object'i temsil edip etmediği önemlidir.

Test mantığı:

```text
owner_id = authorized user
id        = victim's object
```

Eğer backend ownership ilişkisini doğrulamıyorsa authorization mismatch
oluşabilir.

Bu pattern özellikle:

- files
- invoices
- orders
- messages
- tickets
- projects
- media
- reports

gibi resource'larda değerlidir.

---

# 8. REST API'de sistematik test

## 8.1 Baseline

A hesabıyla:

```http
GET /api/orders/1001
Authorization: Bearer TOKEN_A
```

Önce gerçekten A'nın object'i olduğunu doğrula.

## 8.2 Cross-user test

B'nin object'i:

```text
order_id = 1002
```

A'nın tokenı değişmeden:

```http
GET /api/orders/1002
Authorization: Bearer TOKEN_A
```

## 8.3 Sonucu doğrula

Beklenen:

```text
A token + A object → 200
A token + B object → 403/404
```

Vulnerable:

```text
A token + B object → B'nin protected data'sı
```

Aynısını B tokenı + A object ile ters yönde de doğrula.

---

# 9. GET dışındaki methodlar

IDOR yalnızca read değildir.

## Read

```http
GET /api/orders/1002
```

## Modify

```http
PUT /api/orders/1002
```

## Delete

```http
DELETE /api/orders/1002
```

## Action

```http
POST /api/orders/1002/cancel
POST /api/orders/1002/refund
GET  /api/files/1002/download
POST /api/users/1002/export
POST /api/messages/1002/archive
```

Özellikle action endpoint'lerinde authorization middleware/controller farkları
olabileceğinden kontrol önemlidir.

---

# 10. Header'da IDOR

IDOR URL'de olmak zorunda değildir.

Örnek:

```http
GET /api/profile HTTP/2
Authorization: Bearer TOKEN_A
X-User-ID: 111
```

B'nin ID'si `222` ise:

```http
GET /api/profile HTTP/2
Authorization: Bearer TOKEN_A
X-User-ID: 222
```

ve B'nin private profile'ı dönüyorsa custom header object/user identity
kaynağı olarak kullanılıyor olabilir.

İncelenecek header isimleri:

```text
X-User-ID
X-User-Id
X-Account-ID
X-Customer-ID
X-Client-ID
X-Member-ID
X-Profile-ID
X-Organization-ID
X-Org-ID
X-Tenant-ID
X-Company-ID
X-Project-ID
X-Owner-ID
X-Resource-ID
X-Object-ID
X-Document-ID
X-File-ID
```

Ayrıca uygulamaya özel:

```text
X-User
X-Account
X-Customer
X-Client
X-Owner
X-Tenant
X-Context
X-Acting-User
X-Impersonate-User
```

**Header'ın varlığı tek başına IDOR değildir.** Sunucunun değeri authorization
kararında nasıl kullandığı doğrulanmalıdır.

---

# 11. Cookie'de IDOR

Örnek:

```http
GET /api/profile
Cookie: session=ABC123; user_id=111
```

Normal tasarımda kullanıcı kimliği güvenilir session state'inden çıkarılmalıdır.

Test sırasında yetkili scope içinde `user_id`, `account_id`, `customer_id`,
`profile_id`, `owner_id`, `tenant_id` gibi client-controlled değerlerin
authorization'da kullanılıp kullanılmadığı araştırılabilir.

Örnek mantık:

```text
session → A
user_id → B
response → B
```

Bu durumda authorization identity kaynağı hatalı olabilir.

---

# 12. GraphQL IDOR/BOLA

GraphQL'de URL'de object ID görünmeyebilir.

Örnek:

```http
POST /graphql
Authorization: Bearer TOKEN_A
Content-Type: application/json

{
  "query": "query { user(id: \"111\") { id email name } }"
}
```

A'nın tokenıyla:

```graphql
query {
  user(id: "222") {
    id
    email
    name
  }
}
```

B'nin private bilgileri dönüyorsa BOLA/IDOR söz konusudur.

## GraphQL variables

Ayrıca:

```json
{
  "query": "query GetUser($id: ID!) { user(id: $id) { id email } }",
  "variables": {
    "id": "222"
  }
}
```

gibi variable'ları incele.

## GraphQL nested resolver

Örnek:

```graphql
query {
  account(id: "111") {
    orders {
      id
      invoice {
        id
        downloadUrl
      }
    }
  }
}
```

`account` authorization'ı doğru olsa bile `invoice` resolver'ı ayrı authorization
yapmıyorsa object-level bypass çıkabilir.

Bu nedenle GraphQL'de:

- root object
- nested object
- list item
- connection/edge
- mutation input
- mutation target
- resolver-specific ID

ayrı ayrı düşünülmelidir.

## GraphQL mutation

```graphql
mutation {
  updateOrder(id: "222", status: "cancelled") {
    id
    status
  }
}
```

A'nın tokenıyla B'nin order'ı değişiyorsa write/action authorization problemi vardır.

---

# 13. File/download IDOR

Özellikle:

```text
/download/{id}
/files/{id}
/attachments/{id}
/documents/{id}
/media/{id}
/export/{id}
```

ve JSON'daki:

```text
file_id
document_id
attachment_id
download_id
export_id
```

alanlarına bak.

Dosya ID'si UUID olsa bile IDOR olabilir:

```text
UUID tahmin edilemiyor
        ≠
authorization var
```

Başka bir kullanıcının UUID'si uygulamanın başka bir response'undan,
download linkinden, notification'dan veya başka yetkili veri akışından elde
edilebiliyorsa object-level authorization yine test edilebilir.

---

# 14. UUID ve opaque identifier

Şu:

```text
/api/files/914b87a8-01ce-d507-058f-8c86437afd02
```

gibi UUID kullanımı IDOR'u ortadan kaldırmaz.

Önemli ayrım:

```text
Unpredictable identifier
        ≠
Authorization
```

UUID'yi tahmin etmeye çalışmak yerine yetkili uygulama akışlarından elde edilen
object references üzerinden ownership test etmek daha anlamlıdır.

---

# 15. Base64/encoding ile taşınan object reference

Base64 encryption değildir.

Örneğin:

```text
MTAx
```

Base64 decode edildiğinde:

```text
101
```

olabilir.

Uygulama:

```text
object_id = Base64(user_id)
```

kullanıyorsa aynı ownership testi uygulanabilir:

```text
A object
   ↓
encoded reference
   ↓
B object reference
   ↓
A token + B reference
```

Başka encoding/representation örnekleri:

```text
plain ID
URL encoding
Base64
Base64URL
JSON string
JSON number
opaque token
UUID
hash-like identifier
```

Ancak bir encoding'in değiştirilebilmesi tek başına authorization bypass değildir.

---

# 16. Canonicalization / normalization

Aynı mantıksal değerin farklı katmanlarda farklı yorumlanması authorization
hatalarına yol açabilir.

Örneğin:

```text
gateway
  ↓
URL decode
  ↓
application
  ↓
JSON decode
  ↓
backend service
```

Bir katman:

```text
"123"
```

diğer katman:

```text
123
```

olarak ele alıyorsa veya normalization sırası farklıysa authorization
decision ile resource lookup ayrışabilir.

Yetkili testlerde kavramsal olarak şu representation sınıfları incelenebilir:

```text
123
"123"
URL-encoded representation
Base64/Base64URL representation
UUID representation
opaque reference
```

Ama yalnızca uygulamanın gerçekten bu formatları desteklediği durumda.

---

# 17. Hash-like reference değerleri

Bazı API'lerde:

```http
X-Account: 7f83b165...
```

gibi kullanıcıya opaque/hash görünümlü değerler gönderilebilir.

Bunun:

```text
hash("admin")
```

olduğu düşünülse bile kesin varsayım yapılmamalıdır.

Değer:

- hash
- encoding
- encryption
- signed identifier
- opaque database key
- random identifier

olabilir.

Önemli test:

> Server client-controlled representation'ı hangi aşamada canonical identity/object
> reference'a dönüştürüyor ve authorization hangi representation üzerinde
> yapılıyor?

Bir string'in beklenmedik biçimde kabul edilmesi ancak unauthorized resource
erişimi veya authorization decision üzerinde etkisi varsa güvenlik bulgusuna
dönüşür.

## Representation karşılaştırma tablosu

Agent'ın "obfuscation ≠ authorization" ayrımını hızlı yapabilmesi için:

| Representation | Decode edilebilir mi? | Değiştirilebilir mi? | Tek başına authorization sağlar mı? |
|---|---|---|---|
| Base64 | Evet, trivially | Evet, genellikle | Hayır — sadece encoding |
| UUID (v4/random) | Hayır | ID'ye bağlı, tahmin edilemez olmalı | Hayır — ama tahmin edilemezlik brute-force'u zorlaştırır |
| Hash (MD5/SHA vb.) | Tek yönlü, decode edilemez | Yeniden hesaplamak gerekir | Hayır |
| HMAC | Hayır | Secret bilinmeden değiştirilemez | Integrity sağlayabilir, ama authorization kararı için tek başına yeterli değildir |
| JWT | Payload (base64) okunabilir | Signature geçersiz kılınmadan değiştirilemez — ama bkz. bölüm 25-26 algoritma/signature doğrulama davranışı | Signature doğrulaması + claim kontrolü olmadan tek başına yeterli değildir |
| Signed URL (presigned) | Kısmen (URL parametreleri görünür) | İmza olmadan değiştirilemez | Scope/expiry'ye bağlı — bkz. bölüm 100 |
| Opaque ID (server-side lookup key) | Bilinmez, anlamsız string | Uygulamaya bağlı | Hayır — ownership kontrolü backend'de ayrıca yapılmalı |

Bu tablonun özeti: **hiçbir representation türü, kendi başına bir
authorization mekanizması değildir.** Her biri yalnızca "tahmin
edilebilirliği zorlaştırma" seviyesinde fayda sağlar; asıl object-level
authorization kontrolü backend'de, her request'te ayrıca yapılmak
zorundadır. Bir ID'nin "tahmin edilemez" (UUID, hash, opaque) olması,
o ID özel bir yolla (leak, IDOR başka bir endpoint'ten, response'ta
sızıntı) ele geçirildiğinde arkasındaki authorization kontrolünün var
olup olmadığı sorusunu ortadan kaldırmaz — bkz. bölüm 14 "UUID ve opaque
identifier."

---
