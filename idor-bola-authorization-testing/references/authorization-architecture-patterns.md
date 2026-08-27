# 18. Birden fazla servis ve authorization mismatch

Modern sistemlerde:

```text
Client
  ↓
API Gateway
  ↓
Service A
  ↓
Service B
```

olabilir.

Request:

```json
{
  "user_id": "111",
  "document_id": "222"
}
```

Gateway:

```text
user_id == current user
        ↓
        ✓
```

Service B:

```text
document_id = 222
        ↓
object lookup
        ↓
authorization yapılmıyor
```

Sonuç:

```text
Gateway → A
Service B → B object
```

Bu nedenle microservice mimarisinde **identity propagation** ve downstream
authorization sınırları özellikle önemlidir.

---

# 19. Multi-tenant IDOR

SaaS uygulamalarında:

```text
Tenant A
 └── User A
      └── Document 123

Tenant B
 └── User B
      └── Document 456
```

Request:

```http
GET /api/documents/456
Authorization: Bearer TOKEN_A
```

Eğer Tenant A tokenıyla Tenant B resource'u dönüyorsa bu tenant isolation
problemi/BOLA olabilir.

İncelenecek alanlar:

```text
tenant_id
organization_id
workspace_id
company_id
account_id
project_id
```

Şu ilişkileri doğrula:

```text
authenticated user belongs to tenant?
object belongs to tenant?
tenant belongs to account?
project belongs to tenant?
```

**Kanıt standardı — "üyelik kanıtı bulunamadı" ile "üyelik olmadığı doğrulandı" farklıdır:**
`tenant_id` aynı ama `project_id` farklıysa (ör. A: `tenant=T1/project=P1`,
object: `tenant=T1/project=P9`), bunun IDOR sayılabilmesi için A'nın P9
ile ilişkisi konusunda **agent'ın hiç kontrol yapmamış olması** yeterli
değildir — bu durumda doğru STATUS `NOT_TESTABLE`'dır, `CONFIRMED`
değil. Bazı SaaS mimarilerinde "aynı tenant'taki herkes tüm projeleri
görür" meşru bir tasarım kararı olabilir (bkz. yukarıdaki Role × Object
× Action matrisi — "Tenant Admin" ve bazı "Manager" satırları buna
örnektir).

Bunun yerine, A'nın P9 ile ilişkisinin olmadığı **aktif olarak**
doğrulanmalıdır — ör.:

```text
1. A'nın kendi "my projects"/dashboard listeleme endpoint'i çağrılır;
   P9 bu listede GÖRÜNMÜYORSA, bu A'nın P9 ile açık bir ilişkisi
   olmadığına dair pozitif bir kanıttır (dokümantasyona gerek yoktur
   — bu, response'ta owner/tenant alanı görmenin ownership kanıtı
   sayılmasıyla aynı mantık: uygulamanın kendi verdiği veri).
2. Tenant-genelinde bir "tüm projeler" görünümü/endpoint'i (varsa) A'nın
   tokenıyla denenir; böyle bir özellik yoksa veya P9'u listelemiyorsa,
   bu da destekleyici kanıttır.
```

Bu iki kontrolden **en az biri** yapılıp P9'un A'ya açık şekilde
görünmediği/tanınmadığı teyit edildiğinde, `target_owner_confirmed=yes`
sayılır ve normal CONFIRMED değerlendirmesine girer. Hiçbiri
yapılmadıysa (agent sadece "üyelik kanıtı görmedim" diyorsa, hiç
aramadıysa), sonuç `NOT_TESTABLE` kalır — bu, gerçek bir bulguyu
gizlemez, yalnızca ek bir (genelde tek bir ekstra istekle yapılabilir)
doğrulama adımını zorunlu kılar.

## Ownership yalnızca "user" değildir

Bu bölüm tenant/organization seviyesini kapsıyor, ama genel prensip daha
geniştir: bir object'in "sahibi" (owner) doğrudan bir kullanıcı olmak
zorunda değildir — **team, proje, departman veya servis hesabı da** owner
olabilir. Bu durumda authorization dolaylı bir zincirden geçer:

```text
User A
   │ member_of
   ▼
Team X
   │ owns
   ▼
Document Y
```

`User A → Document Y` erişimi meşrudur çünkü `A`, `Y`'yi sahiplenen
`Team X`'in bir üyesidir — ama bu, `A`'nın `Y`'nin doğrudan owner_id'si
olduğu anlamına gelmez. Test edilmesi gereken tipik ownership zincirleri:

```text
user  → team      → object
user  → project   → object
user  → department → object
user  → service_account → object
user  → role      → object (bazı RBAC modellerinde role'ün kendisi
                              belirli object'lere "sahip" olabilir)
```

Bu, doğrudan bir "user IDOR" bulgusu değildir — kullanıcının kendi ID'si
manipüle edilmiyor olabilir — ama yine de bir **object authorization**
problemidir: `User B` (Team X üyesi olmayan biri) aynı `Document Y`'ye
erişebiliyorsa, kırılan kural `A == owner(Y)` değil, `A member_of
owner_team(Y)` invariant'ıdır (bkz. bölüm 5 "Relationship graph modeli").
Agent, bir object'in owner alanının doğrudan bir user_id mi yoksa bir
team/project/department referansı mı olduğunu recon aşamasında tespit
etmeli ve testini buna göre kurmalıdır.

---

# 20. Alternate endpoint / API version

Ana endpoint korunuyor olabilir:

```text
/api/orders/123 → 403
```

ama aynı object:

```text
/api/orders/123/download
/api/orders/123/export
/api/v2/orders/123
/api/internal/orders/123
```

gibi farklı route'larda farklı middleware veya authorization logic kullanabilir.

Aynı object'in tüm erişim yollarını araştır.

---

# 21. HTTP method mismatch

Aynı resource için methodlar farklı code path kullanabilir:

```text
GET    /api/users/222 → 403
PUT    /api/users/222 → 200
DELETE /api/users/222 → 403
POST   /api/users/222/export → 200
```

Bu nedenle yalnızca GET test edilmemelidir.

---

# 22. WebSocket object authorization

WebSocket mesajlarında URL'de ID olmayabilir.

Örneğin:

```json
{
  "action": "read_message",
  "user_id": "111",
  "message_id": "222"
}
```

veya:

```json
{
  "action": "join_room",
  "room_id": "333"
}
```

Her object reference için ownership/authorization değerlendirilmelidir.

REST API güvenli olup WebSocket consumer'ın authorization'ı eksik olabilir.

---

# 29. En zor IDOR pattern'leri

Öncelikli araştırma alanları:

1. Nested object authorization
2. Parent ID + child ID
3. owner_id + resource_id mismatch
4. Multiple identity/object IDs
5. GraphQL nested resolvers
6. GraphQL mutations
7. Multi-tenant isolation
8. Microservice/gateway authorization mismatch
9. Alternate API versions
10. Download/export/action endpoints
11. WebSocket object references
12. UUID/opaque identifiers
13. Custom header identity
14. Cookie-based identity
15. Encoding/canonicalization mismatches
16. Different HTTP methods
17. Different serializers/parsers
18. Frontend-only authorization assumptions

---

# 30. Frontend vs backend authorization mismatch

Çok önemli pattern:

Request:

```json
{
  "requester_id": "111",
  "account_id": "222"
}
```

Frontend:

```text
requester_id == currentUser
        ↓
        ✓
```

Backend:

```text
account_id → resource lookup
```

ama:

```text
account.owner == currentUser
```

kontrolü yoksa authorization mismatch oluşur.

Agent şu soruyu sormalıdır:

> Frontend hangi ID'yi doğruluyor, gateway hangi ID'yi doğruluyor ve gerçek
> resource lookup hangi ID ile yapılıyor?

---

# 45. Batch / bulk endpoint IDOR

Tekil object endpoint'i korunsa bile batch/bulk endpoint'ler ayrı authorization
mantığı kullanabilir:

```http
POST /api/orders/bulk-fetch
Authorization: Bearer TOKEN_A

{
  "order_ids": ["1001", "1002", "1003"]
}
```

Test edilecek senaryo:

```text
1001 = A'nın objecti
1002 = B'nin objecti  (araya eklendi)
1003 = C'nin objecti  (araya eklendi)
```

Vulnerable backend, dizideki her ID için ayrı ayrı ownership kontrolü
yapmayıp yalnızca ilk/tek ID'yi doğrulayabilir ya da hiç doğrulamayabilir.

Aynı pattern şu durumlarda da geçerlidir:

```text
bulk delete
bulk update
bulk export
bulk share
bulk assign
CSV/Excel toplu işlem endpoint'leri
```

---

# 46. Mass assignment ile object-level authorization ilişkisi

Mass assignment kendi başına ayrı bir zafiyet sınıfıdır, ancak object-level
authorization ile kesiştiği önemli bir nokta vardır: request body'e
normalde forma dahil olmayan bir ownership/ilişki alanı eklenmesi.

Örnek:

```http
PUT /api/documents/555
Authorization: Bearer TOKEN_A

{
  "title": "Updated title",
  "owner_id": "222"
}
```

veya:

```json
{
  "title": "Updated title",
  "account_id": "222",
  "tenant_id": "999"
}
```

Eğer sunucu bu alanları filtrelemeden kabul ediyorsa, saldırgan kendi
object'inin ownership/tenant ilişkisini başka bir kullanıcı/tenant'a
devredebilir veya tam tersi, başka birinin object'ini kendi hesabına
"transfer" edebilir. Bu, klasik read/write IDOR'dan farklı ama ilişkili
bir authorization hatasıdır ve ayrı raporlanmalıdır.

---

# 48. Race condition (TOCTOU) ile IDOR/BOLA kesişimi

Bazı authorization kontrolleri "check sonra act" (time-of-check to
time-of-use) modeliyle çalışır. Eşzamanlı gönderilen request'ler bu aralığı
istismar edebilir:

```text
Request 1: ownership check → geçer
Request 2 (paralel): ownership check → geçer
        ↓
her iki request de aynı anda action'ı tamamlar
        ↓
state, tek bir authorization kararının koruyabileceğinden farklı sonuca ulaşır
```

Özellikle:

```text
paylaşım/transfer endpoint'leri
bakiye/kredi kullanan action'lar
tek kullanımlık kupon/kod/link
object ownership değiştiren işlemler
```

için object-level authorization kontrolünün race-safe olup olmadığı
(idempotency, locking, atomic check-and-set) değerlendirilebilir. Bu genellikle
ayrı bir race-condition bulgusu olarak raporlanır ama kök neden çoğu zaman
zayıf object-level authorization'dır.

## If-Match / ETag ile optimistic locking IDOR

Race condition'dan (eşzamanlı istekler) farklı olarak, bazı API'ler
optimistic locking için conditional request header'ları kullanır:

```http
PUT /api/orders/1002
If-Match: "abc123"
```

Beklenen davranış: sunucu `If-Match` değerini, `1002` object'inin
**güncel** ETag'i ile karşılaştırır; eşleşmezse `412 Precondition
Failed` döner. Buradaki authorization-ilişkili soru şudur:

```text
1. If-Match değeri client-controlled ve sunucu bunu yalnızca "değişti
   mi değişmedi mi" kontrolü için mi kullanıyor, yoksa isteği yapan
   kullanıcının bu object'e erişim yetkisi olup olmadığını da ayrıca
   mı kontrol ediyor?
2. Saldırgan, B'nin object'ine ait geçerli bir ETag'i (ör. B'nin
   response'undan, bkz. bölüm 50 "Object Reference Acquisition")
   elde edip, kendi (yetkisiz) isteğinde bu ETag'i kullanarak
   overwrite işlemini "precondition geçti" diye tamamlayabiliyor mu?
```

Burada asıl zafiyet ETag mekanizmasında değil — `If-Match` sadece bir
concurrency kontrolüdür — sunucunun ETag doğrulamasını object-level
authorization kontrolünün **yerine** koyup koymadığındadır. Bu iki
kontrol birbirinden bağımsız çalışmalı ve her ikisi de ayrı ayrı
sağlanmalıdır.

---

# 49. Paylaşılan cache (shared cache) kaynaklı authorization karışması

Eğer response'lar bir CDN, reverse proxy veya application-level cache
tarafından önbelleğe alınıyorsa ve cache key authenticated identity'yi
içermiyorsa:

```text
User B → GET /api/profile → response cache'e yazılır (identity'siz key)
User A → GET /api/profile → aynı cache key → B'nin response'u döner
```

Bu klasik IDOR'dan farklıdır: saldırgan bir ID değiştirmez, sadece normal
request atar ama başka kullanıcının cache'lenmiş verisini alır. Test
noktaları:

```text
Cache-Control / Vary header'ları
CDN edge cache davranışı
kullanıcıya özel endpoint'lerin cache'lenip cache'lenmediği
Authorization header Vary listesinde mi
```

Bu bulgu genellikle "cache deception" veya "sensitive data caching" olarak
sınıflandırılır ancak object-level veri sızıntısına yol açtığı için IDOR/BOLA
testi kapsamında değerlendirilmelidir.

---

# 50. Second-order (dolaylı) object reference

Bir object reference'ın kaynağı doğrudan URL/JSON olmayabilir; başka bir
endpoint'in response'undan, bir notification'dan veya bir export dosyasından
elde edilip başka bir endpoint'te kullanılabilir:

```text
Endpoint A → response içinde internal_id, file_token, share_token döner
        ↓
Endpoint B → bu token/id ile object'e erişim sağlar
```

Test mantığı:

```text
1. A hesabıyla normal akışı tamamla, response'larda görünen
   tüm ID/token/reference değerlerini kaydet
2. Bu değerlerin object-level authorization'ı bypass etmek için
   başka endpoint'lerde kullanılıp kullanılamayacağını değerlendir
3. Özellikle "internal" görünen, dokümante edilmemiş veya
   debug/log response'larında sızan referanslara dikkat et
```

Bu pattern, tekil endpoint bazlı testlerin kaçırdığı, çapraz-endpoint
zincirleme authorization hatalarını ortaya çıkarabilir.

## Object Reference Acquisition — B'nin object referansı nereden bulunur?

Cross-user testi (bölüm 8, 31) için "B'ye ait bir object ID" gerekir.
Agent bunu tahmin etmekle sınırlı kalmamalıdır; aşağıdaki kaynaklar
sistematik olarak taranmalıdır:

```text
1. B hesabının kendi response'u (ikinci bir test hesabı varsa)
2. Ortak/shared resource (paylaşılan proje, davet, yorum altındaki
   diğer kullanıcı referansları)
3. A'nın zaten erişebildiği başka bir endpoint (ör. bir liste
   endpoint'i A'nın kendi kaydıyla birlikte başkalarının ID'lerini
   de sızdırıyor olabilir)
4. Notification / activity feed (bildirimler genellikle başka
   kullanıcıların object ID'lerine referans verir)
5. List/search endpoint (arama sonuçları, autocomplete/typeahead)
6. Download/export URL (bkz. bölüm 91, 100 — dosya adı/URL içindeki
   ID)
7. GraphQL nested response (bir query, ilişkili obje'ler üzerinden
   dolaylı olarak başka kullanıcıların ID'lerini döndürebilir)
8. WebSocket/SSE mesajları (bkz. bölüm 22, 72, 73 — broadcast
   mesajlarında başka kullanıcıların object referansı geçebilir)
9. Pagination/cursor token'ı (decode edildiğinde owner/tenant bilgisi
   taşıyabilir — bkz. bölüm 58 checklist madde 29)
10. Frontend state / API response'da sızan debug/internal alanlar
    (bkz. bu bölümün üstündeki second-order reference mantığı)
11. Sıralı/tahmin edilebilir ID'ler (numeric ID artışı, timestamp
    tabanlı ID) — yalnızca ID formatı buna izin veriyorsa
12. OpenAPI/Swagger/API dokümantasyonu sızıntısı (`/swagger.json`,
    `/api-docs`, `/openapi.yaml` gibi dokümante edilmiş veya
    unutulmuş dokümantasyon endpoint'leri, internal endpoint'leri ve
    parametre isimlerini açığa çıkarabilir; bazı durumlarda örnek/demo
    response'larda gerçek object ID'leri bile sızabilir)
```

Bu kaynaklardan elde edilen her referans, bölüm 8/31'deki A/B token-swap
testine doğrudan girdi olarak kullanılabilir. Agent, bir object reference
bulduğunda önce **hangi kaynaktan geldiğini** not etmelidir — çünkü bu,
raporlanacak bulgunun "nasıl keşfedildiği" kısmını oluşturur ve bazı
durumlarda (ör. madde 3, 4, 5, 12) referansın sızması **kendi başına ayrı
bir bulgu** olabilir (bilgi ifşası), object'e erişimin kendisi ayrı bir
IDOR bulgusu olsa bile.

**Öncelik notu:** Bu 12 kaynak eşit olasılıkla sonuç vermez; agent zaman/
request bütçesini kör biçimde dağıtmak yerine kendi endpoint yüzeyine göre
önceliklendirmelidir. Basit REST kaynaklarında (madde 1, 3, 5) genellikle
düşük efor ile hızlı sonuç alınır. GraphQL/batch/WebSocket ağırlıklı
API'lerde (madde 7, 8) efor daha yüksektir ama getirisi de büyüktür, çünkü
bu API'lerde object reference çoğunlukla doğrudan URL/JSON'da değil nested
response veya broadcast mesajında saklıdır — bu da tam olarak Layer 1/2
testlerinin "hiç tetiklenmeme" riskinin en yüksek olduğu senaryodur. Bir
endpoint yüzeyinde bu taramanın hiçbirinin B'ye ait bir referans
üretmediği durumda, sonuç `NOT_TESTABLE` olarak işaretlenmeli, bölüm 8/31
testi hiç çalıştırılmamış gibi atlanmamalıdır (aşağıdaki "Yalnızca tek
test hesabı" akışıyla karıştırılmamalı — bu not iki hesap mevcutken bile
geçerlidir).

## Yalnızca tek test hesabı mevcutsa (B hesabı yoksa)

Yukarıdaki kaynakların çoğu iki test hesabı (A ve B) varlığını varsayar.
Pratikte agent'ın elinde yalnızca bir hesap (A) olabilir ve ikinci bir
hesap oluşturmak mümkün olmayabilir (davet-only kayıt, ödeme gerektiren
plan, manuel onay vb.). Bu durumda sıra şöyle işler:

```text
1. ID enumeration (yalnızca rate limit ve kapsam kurallarına uyarak)
   ile mevcut object'leri keşfet, response'ta dönen owner_id/tenant_id
   alanlarından A'ya ait OLMAYANLARI hedefle.
2. Public/shared resource'lar üzerinden (yorumlar, davetler, ortak
   proje/takım üyeleri) başka kullanıcıların ID'lerini topla — bu
   kullanıcılar "gerçek B" değildir ama object referansı olarak
   kullanılabilir.
3. Yukarıdaki 12 kaynaktan (özellikle 3, 4, 5, 12) A'nın erişebildiği
   ama sahibi olmadığı object referansları ara.
4. Hiçbir yolla A'ya ait olmayan bir object referansı elde
   edilemiyorsa, test bölüm 109'daki output contract'ta
   `STATUS: NOT_TESTABLE` olarak işaretlenmelidir — tahmine dayalı
   veya doğrulanamamış bir object üzerinde test yapılmamalı, sonuç
   spekülatif bir bulgu gibi sunulmamalıdır.
```

---

# 68. Array Index / Offset Manipülasyonu ile IDOR

Listeleme endpoint'lerinde offset/limit manipülasyonu:

```http
GET /api/messages?offset=0&limit=10
GET /api/messages?offset=-10&limit=10
GET /api/messages?offset=999999&limit=10
```

Negatif offset veya çok büyük offset değerleri beklenmedik veri döndürebilir. Özellikle:

```text
offset, skip, start, from, page, cursor, next, prev
```

parametreleri test edilmelidir.

---
