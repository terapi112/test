# 31. Authorization matrix

İki hesapla en güçlü temel test:

| Test | Token | Object | Beklenen |
|---|---|---|---|
| 1 | A | A | Allow |
| 2 | B | B | Allow |
| 3 | A | B | Deny |
| 4 | B | A | Deny |

Ek olarak:

| Test | Authentication | Object | Beklenen |
|---|---|---|---|
| 5 | None | A | Deny |
| 6 | Invalid | A | Deny |
| 7 | Expired | A | Deny |

Bulguyu doğrulamak için response body'deki ownership göstergelerini
kaydet:

```text
user_id
owner_id
account_id
tenant_id
email
object id
resource URL
```

## Role × Object × Action matrisi (rol tabanlı sistemler için)

İki hesaplı A/B matrisi düz (flat) yetki modellerinde yeterlidir. Ancak
role-based access control (RBAC) içeren sistemlerde (user/manager/admin/
tenant-admin gibi hiyerarşik roller), yalnızca "kim + hangi object" değil,
"hangi rol + hangi object + hangi aksiyon" boyutu da test edilmelidir.
Örnek matris:

| Aktör | Object A (kendi) | Object B (aynı takım) | Object C (başka tenant) |
|---|---|---|---|
| User A | ✓ read/write | ✗ deny | ✗ deny |
| Manager (A'nın yöneticisi) | ✓ read/write | ✓* read only mi, write de mi? | ✗ deny beklenir |
| Admin (aynı tenant) | ✓ | ✓ | ✗ deny beklenir |
| Tenant Admin | ✓ | ✓ | ✗ deny beklenir (cross-tenant) |
| Süper Admin / Platform Admin | ✓ | ✓ | ✓ (meşru, dokümante edilmiş olmalı) |

Test edilmesi gereken asıl soru işaretleri `✓*` ile işaretlenen hücrelerdir
— yani "bu rolün bu object'e erişimi olmalı mı, olmalıysa hangi aksiyonlar
(read/write/delete) için" net değilse, bu agent'ın recon aşamasında
uygulamanın dokümantasyonundan/UI davranışından çıkarması gereken bir
varsayımdır. Her rol × object kombinasyonu için ayrı ayrı:

```text
1. Beklenen davranış nedir? (dokümantasyon, UI'da görünen/görünmeyen
   aksiyonlar üzerinden çıkarım yapılır)
2. Gerçek davranış nedir? (API'ye doğrudan istek atılarak test edilir)
3. İkisi arasında fark varsa — ve fark "daha fazla erişim" yönündeyse —
   bu bir authorization bulgusudur (klasik IDOR olmayabilir, broken
   function/role-level authorization olarak sınıflandırılabilir, ama
   aynı kanıt standardına — bölüm 37 — tabidir).
```

Yalnızca iki test hesabı (A/B) yerine, mümkünse en az bir "daha yetkili"
(manager/admin) ve bir "daha az yetkili" hesap daha edinilmesi, bu
matrisin tam doldurulabilmesi için önerilir.

---

# 32. Burp Suite workflow

## Phase 1 — Discovery

Proxy/HTTP history'den:

- URL path IDs
- query IDs
- JSON IDs
- GraphQL IDs
- headers
- cookies
- download URLs
- WebSocket messages

çıkar.

## Phase 2 — Classification

Her request'i:

```text
identity
object
owner
tenant
parent
child
action
```

olarak sınıflandır.

## Phase 3 — Baseline

A hesabı + A object.

## Phase 4 — Cross-user

A hesabı + B object.

## Phase 5 — Reverse

B hesabı + A object.

## Phase 6 — Action tests

GET/POST/PUT/PATCH/DELETE ve action endpointleri.

## Phase 7 — Alternate paths

v1/v2, export/download, nested route, GraphQL mutation, WebSocket.

## Phase 8 — Evidence

Request + response + ownership relationship + impact.

---

# 33. Intruder'ın doğru kullanımı

Intruder object ID keşfi için yardımcı olabilir.

Örneğin:

```http
GET /api/orders/§OBJECT_ID§
```

Status, response length veya response content farklılıkları gözlemlenebilir.

Fakat:

```text
200 = IDOR
```

değildir.

Enumeration yalnızca object'lerin mevcut olabileceğini gösterebilir.

Gerçek IDOR kanıtı:

```text
Attacker session
+
victim object
+
victim protected data
```

olmalıdır.

Hedef sistemin rate limit, scope ve program kurallarına uyulmalıdır.

---

# 34. Katana/recon workflow'a entegrasyon

Endpoint discovery sonrası IDOR adayları çıkarılabilir:

```text
subdomains
    ↓
httpx
    ↓
Katana
    ↓
endpoints
    ↓
parameter/object-reference extraction
    ↓
IDOR candidate list
    ↓
authenticated validation
    ↓
A/B ownership testing
    ↓
confirmed findings
```

Aday pattern'ler:

```text
/api/users/{id}
/api/orders/{id}
/api/files/{id}
/api/accounts/{id}
/api/documents/{id}
/api/users/{user}/orders/{order}
```

JSON ve GraphQL için de benzer semantic extraction yapılmalıdır.

---

# 35. Agent için otomatik aday çıkarma mantığı

Agent aşağıdaki sinyalleri işaretleyebilir:

```text
*_id
*Id
id
uuid
guid
owner
owner_id
user
user_id
account
account_id
customer
customer_id
tenant
tenant_id
organization
organization_id
project
project_id
resource
resource_id
object
object_id
file
file_id
document
document_id
attachment
attachment_id
```

Ayrıca:

```text
/users/{x}
/accounts/{x}
/orders/{x}
/files/{x}
/documents/{x}
```

gibi numeric, UUID veya opaque path segmentlerini işaretle.

GraphQL'de:

```text
id:
userId:
accountId:
resourceId:
ownerId:
input.id
input.userId
```

gibi alanları çıkar.

---

# 36. False positive filtreleme

Agent şu durumları otomatik olarak IDOR diye raporlamamalıdır:

## Sadece ID değişti

```text
1001 → 1002
```

## Sadece 200 döndü

```text
200 OK
```

## Public resource

Kaynak zaten herkese açıksa IDOR değildir.

## Aynı kullanıcıya ait başka object

Object B de A'ya aitse cross-user authorization ihlali yoktur.

## Generic response

```json
{"success": true}
```

tek başına private object erişimi kanıtlamaz.

## Random/opaque ID görünümü

UUID veya hash-like değer görmek tek başına bulgu değildir.

---

# 37. Bulguyu doğrulama standardı

Bir IDOR/BOLA bulgusu için mümkün olduğunca şu dört parçayı göster:

```text
1. Authenticated identity = A
2. Object owner = B
3. Request contains B's object reference
4. Server returns/modifies B's protected resource
```

Örnek:

```text
TOKEN_A
OBJECT_ID = B_OBJECT
       ↓
200 OK
       ↓
owner_id = B
email = B
```

Bu, yalnızca:

```text
GET /api/object/123 → 200
```

göstermekten çok daha güçlüdür.

## Response comparison stratejisi (semantic diff)

`status == 200` kontrolü tek başına yeterli değildir — birçok API, yetkisiz
isteklere de 200 dönüp boş/generic bir body verebilir, ya da tam tersi 403
dönüp aslında body'de veri sızdırabilir. Agent, iki response'u (baseline
authorized request vs. cross-user request) karşılaştırırken yalnızca
status code'a değil, aşağıdaki alanların **tamamına** bakmalı ve bunları
sistematik olarak çıkarmalıdır:

```text
- status_code
- content_length (baseline ile fark var mı?)
- response body'deki JSON key'leri (baseline'da olmayan yeni alanlar
  ortaya çıktı mı?)
- object ID'ler (response içindeki id, resource id vb. gerçekten
  istenen B object'ine mi ait?)
- owner_id / user_id / created_by gibi ownership alanları
- tenant_id / organization_id / workspace_id
- email / username / phone gibi PII alanları
- resource URL / download URL / file path (başka bir kullanıcının
  dosyasına işaret ediyor mu?)
- response header'ları (ör. Content-Disposition içindeki dosya adı,
  ETag, Last-Modified — B'nin verisine ait izler taşıyabilir)
- error message içeriği (bazen "hata" mesajı bile B'ye ait bir detay
  sızdırabilir, ör. "User b@example.com not found" gibi)
- pagination count / total (B'nin kayıtları sayıma dahil mi?)
- array length (normalde 0 dönmesi gereken bir liste, cross-tenant
  istekte doluysa bu tenant isolation ihlalidir)
```

**Ownership evidence extraction**, agent'ın otomatik olarak yapması
gereken bir adımdır: response body JSON ise, agent parse edip içindeki
`*_id`, `owner*`, `tenant*`, `email`, `username` gibi alanları çıkarmalı ve
bunları request'te kullanılan token'ın kimliğiyle karşılaştırmalıdır.
Örneğin:

```json
{
  "id": "222",
  "owner_id": "B",
  "tenant_id": "T2",
  "email": "victim@example.com"
}
```

Token'ın kimliği `A` ve `tenant_id = T1` olduğu bilindiğinde, yukarıdaki
response tek başına (status code'dan bağımsız olarak) bir BOLA kanıtıdır:
`owner_id != A` ve `tenant_id != T1`. Bu semantic diff yaklaşımı, hem
false-positive'i azaltır (yalnızca status'e bakan kaba testler `200 ama
boş body` durumunu yanlışlıkla bulgu sayabilir) hem de false-negative'i
azaltır (`403` dönse bile body'de sızıntı olan durumları yakalar).

**Önemli önkoşul:** Bu örnek, `owner_id`'nin doğrudan bir **kullanıcıyı**
temsil ettiği ve tenant'ın da tekil bir hesap sınırı olduğu en yaygın
durumu varsayar. Eğer object'in owner alanı bir **team/project/department**
referansıysa (bkz. bölüm 19 "Ownership yalnızca 'user' değildir"), `owner_id
!= A` tek başına yeterli kanıt DEĞİLDİR — çünkü A, o team/project'in meşru
bir üyesi olabilir (`A member_of owner_team(object)`). Bu durumda agent,
BOLA kanıtı üretmeden önce A'nın ilgili team/project/tenant ile üyelik
ilişkisini de kontrol etmelidir; aksi halde meşru bir paylaşılan-kaynak
erişimi yanlışlıkla BOLA olarak raporlanır (false positive). Bu önkoşul
yalnızca owner alanı team/project/department gibi çoğul bir varlığa işaret
ettiğinde devreye girer — sıradan user-to-user IDOR testlerinde (owner
doğrudan bir kullanıcıysa) yukarıdaki kural aynen geçerlidir.

## Confidence score

Yukarıdaki dört-parçalı kanıt standardı ile "sadece ID değiştim, 200
aldım" arasındaki farkı **sayısallaştırmak**, agent'ın erken/zayıf
sonuçları bulgu diye raporlamasını yapısal olarak engeller:

```text
0 — Sadece ID değiştirildi, response henüz incelenmedi
1 — Yalnızca status code farklı (200 vs 403) gözlemlendi
2 — Response içeriği (content-length, body) baseline'dan farklı,
    ama içerik henüz owner/tenant'a bağlanmadı
3 — Object ID eşleşti AMA response'ta ownership/PII alanı yok
    (ör. yalnızca {"id": "222", "status": "active"} döndü — doğru
    object'e ulaşıldı ama kime ait olduğu response'tan doğrulanamıyor)
4 — Object ID eşleşti VE response'ta B'ye ait ownership/PII alanı var
    (ör. {"id": "222", "owner_id": "B", "email": "victim@..."} —
    owner_id/tenant_id/email gibi alanlar B'ye işaret ediyor)
5 — Protected data/action kesin doğrulandı (B'nin gerçek verisi
    okunabildi VEYA B'nin object'i üzerinde değişiklik/silme/aksiyon
    gerçekleştirilebildiği doğrulandı)
```

Not (write/delete/action endpoint'leri için second-order verification):
Bir `PUT`/`PATCH`/`DELETE`/action isteği çoğu zaman response body'sinde
B'ye ait ownership/PII alanı döndürmez (ör. yalnızca `{"success": true}`).
Bu durumda skor mekanik olarak 3'te takılı kalmamalıdır — response
gövdesi yerine **işlemin etkisi ikinci bir çağrı ile** doğrulanmalıdır:
işlemden sonra B'nin object'i (varsa B'nin kendi tokenıyla, ya da yetki
dahilinde başka bir okuma yoluyla) sorgulanıp değiştiğinin/silindiğinin/
etkilendiğinin teyit edilmesi durumunda confidence doğrudan 5'e
yükseltilir. Bu ikincil doğrulama yapılmadıysa (ör. B'nin hesabına
erişim yoksa) sonuç 3'te (candidate) kalır ve insan teyidi notuyla
sunulur — "işlem başarılı göründü ama etkisi doğrulanamadı" ayrımı
raporda açıkça belirtilmelidir.

**Nedensellik şartı:** Confidence 5'e yükseltmek için "sonradan
değişmiş" gözlemi tek başına yeterli değildir — değişikliğin
**gönderilen isteğin kendisinden** kaynaklandığı gösterilmelidir,
başka bir eşzamanlı işlemden (ör. object'i normal şekilde kullanan
gerçek B kullanıcısından, bir arka plan job'ından) değil. Bunun için:

```text
1. İstekten HEMEN ÖNCE B'nin object'inin mevcut durumu okunur (before).
2. İstek gönderilir.
3. İstekten HEMEN SONRA B'nin object'i tekrar okunur (after).
4. before ≠ after VE değişen alan(lar), gönderilen isteğin payload'ıyla
   tutarlı mı (ör. PATCH'te "status": "approved" gönderildiyse,
   after'ta gerçekten status=approved olmalı — rastgele/ilgisiz bir
   alanın değişmesi yeterli kanıt değildir).
```

`before → istek → after` zinciri bu şekilde sıkı tutulmadan (ör.
"birkaç dakika sonra tekrar kontrol ettim, değişmiş" gibi gevşek bir
zaman aralığıyla) elde edilen bir gözlem, confidence 5 için yeterli
sayılmaz — bu durumda sonuç yine 3-4 (candidate/strong candidate)
seviyesinde kalır ve raporda "etkinin isteğe atfedilebilirliği net
değil" notu eklenir.

Not: Çoğu API'de object ID'nin kendisi response'ta zaten `id` alanı
olarak döner ve genellikle bir ownership alanıyla (owner_id, user_id,
email vb.) birlikte gelir; bu durumda 3'e ulaşan bir sonuç doğrudan 4'e
de ulaşır ve iki seviye pratikte birleşir. 3 ile 4 arasındaki ayrım asıl
şu API'lerde anlamlıdır: object'in **var olduğu** doğrulanabiliyor ama
response'ta hiçbir ownership/PII alanı yoksa (ör. yalnızca durum/flag
dönen bir endpoint), bu durumda "doğru object'e ulaşıldı" (3) ile "bu
gerçekten B'nin verisi" (4) ayrı ayrı doğrulanmalıdır — ownership kanıtı
başka bir çağrıdan (ör. aynı ID ile ilişkili bir liste/detay
endpoint'inden) ayrıca teyit edilene kadar sonuç 3'te kalmalıdır.

Eşleştirme:

```text
0-2 → raporlanmaz (yalnızca "incelenmeye değer" not olarak tutulabilir)
3   → candidate (insan teyidi gerekir)
4   → strong candidate
5   → confirmed finding
```

Bu skala, bölüm 36'daki false-positive filtreleme kurallarının (yalnızca
ID değişti, yalnızca 200 döndü, generic response) doğal bir uzantısıdır
— onları ayrık kural listesi yerine tek bir sayısal eşik olarak ifade
eder.

**`INFO_LEAK` sınıfı bulgularda 5 seviyesinin okunuşu:** `INFO_LEAK`
olarak sınıflandırılan bulgularda (ör. bölüm 44 blind IDOR, 403 body'de
sızan e-posta) confidence 5, "B'nin protected object'ine tam erişim"
anlamına gelmez — bunun yerine "sızan spesifik bilginin (existence,
e-posta, tenant adı vb.) gerçekten B'ye ait olduğu bağımsız bir kaynaktan
doğrulandı" anlamına gelir. Skala aynıdır, yalnızca 5. seviyedeki "protected
data/action" ifadesi bu CLASS için "protected bilginin kendisi" olarak
okunmalıdır.

---

# 37a. Test sırasında per-endpoint kanıt kaydı (Evidence Engine)

Bölüm 109'daki "Agent output contract" bir bulgunun **rapor edilme**
anındaki nihai formatıdır. Ama confidence skorunun (bölüm 37) 0'dan 5'e
nasıl ilerlediğini test **sırasında** izleyen bir ara kayıt yoksa, agent
pratikte iki riskten birine düşer: (a) skoru zihinsel olarak atlayıp
doğrudan yüksek bir confidence'a "sezgiyle" ulaşmak, ya da (b) aynı
endpoint'i farklı turlarda tutarsız şekilde değerlendirmek (ör. bir
turda 403 aldığı için `SAFE` işaretlediği bir endpoint'i, object
reference'ı sonradan bölüm 50 taramasıyla bulduğunda yeniden test
etmeyi unutmak).

Bunu önlemek için agent, test ettiği her endpoint için aşağıdaki alanları
içeren bir çalışma kaydı (working record) tutmalı ve bu kaydı testin her
adımında güncellemelidir — bu kayıt son rapor değildir, raporun
üretileceği ara durumdur:

```text
endpoint:            <method + path>
object_refs_found:   <bölüm 3/50'den bulunan tüm reference alanları
                      ve bulundukları kaynak (bkz. bölüm 50 kaynak no)>
actor:                <A — authenticated identity>
target_object:        <B'ye ait olduğu düşünülen object>
target_owner_source:  <B'nin gerçekten B'ye ait olduğu nereden
                      doğrulandı — ör. B'nin kendi session'ı, bir
                      liste endpoint'i, davet kaydı>
baseline_status:      NOT_RUN / PASS / FAIL
                      (A token + A object beklenen şekilde mi
                      davranıyor — bölüm 8.1)
target_owner_confirmed: yes / no
                      (target_object'in gerçekten B'ye ait olduğu
                      bağımsız bir yoldan doğrulandı mı — ör. B'nin
                      kendi session'ı, bir liste/davet endpoint'i;
                      salt bir ID tahmininin 403/404 dönmesi bunu
                      DOĞRULAMAZ. `no` ise cross_user_status ne
                      olursa olsun nihai STATUS asla SAFE olamaz —
                      bkz. aşağıdaki zorunlu kural)
cross_user_status:    NOT_RUN / DENIED / ALLOWED / PARTIAL_LEAK /
                      INCONCLUSIVE / BLOCKED / NOT_TESTABLE
                      (yalnızca "TESTED" yetersizdir — 403/404 →
                      DENIED, 200+B verisi → ALLOWED, 403/404 ama
                      body'de B'ye ait PII/detay sızıyorsa →
                      PARTIAL_LEAK, 200 ama ownership alanı
                      doğrulanamıyorsa → INCONCLUSIVE, 429/WAF-imzalı
                      403/503 → BLOCKED, object referansı hiç
                      bulunamadıysa → NOT_TESTABLE)
signal_families:      <bu endpoint için tetiklenen Layer 3-5 aileleri
                      ve hangi sinyalin bunu tetiklediği — bölüm
                      "Signal-driven test stratejisi"nden>
evidence_fields:      <response'tan çıkarılan owner_id/tenant_id/
                      email/PII alanları — bölüm 37 semantic diff>
confidence:           0-5 (bölüm 37)
status:               SAFE / CANDIDATE / CONFIRMED / NOT_TESTABLE
last_updated_reason:  <bu kaydın en son neden güncellendiği — yeni
                      bir object reference bulunması, yeni bir
                      sinyal ailesi tetiklenmesi vb.>
```

Bu kaydın amacı üç agent davranışını yapısal olarak zorlamaktır:

```text
1. confidence hiçbir zaman "atlanarak" yükselmez — her artış,
   evidence_fields veya cross_user_status'taki somut bir değişikliğe
   bağlı olmalıdır.
2. `target_object` değiştiğinde (ör. bölüm 50 taramasıyla yeni bir B
   referansı bulunması, veya aynı endpoint'te farklı bir B object'i
   denenmesi), yalnızca `cross_user_status`'u `NOT_RUN`'a döndürmek
   YETERSİZDİR — çünkü `target_owner_confirmed`, `target_owner_source`,
   `evidence_fields` ve `confidence` bir **önceki** object'e ait kanıtı
   taşımaya devam eder ve agent bunları yanlışlıkla yeni object'e
   uygulayabilir (ör. B_OBJECT_1 için `target_owner_confirmed=yes,
   confidence=4` iken B_OBJECT_2'ye geçilip yalnızca `cross_user_status`
   sıfırlanırsa, B_OBJECT_2 için hâlâ doğrulanmamış bir ownership/
   confidence görünür). Bu nedenle `target_object` her değiştiğinde
   **tüm object-scoped alanlar** birlikte resetlenir:

   ```text
   target_object:          <YENİ_OBJECT>
   target_owner_source:    RESET
   target_owner_confirmed: no
   evidence_fields:        RESET (boş)
   confidence:             0
   cross_user_status:      NOT_RUN
   status:                 NOT_TESTABLE
   last_updated_reason:    target_object_changed
   ```

   Bu, hiçbir bulguyu engellemez — yalnızca her yeni object'in kendi
   bağımsız kanıt zincirini sıfırdan kurmasını zorunlu kılar; eski bir
   object'te elde edilen yüksek confidence, yeni bir object için
   otomatik olarak geçerli sayılamaz.
3. object_refs_found sonradan güncellenirse (ör. bölüm 50 taramasıyla
   yeni bir B referansı bulunursa) ve bu, mevcut `target_object` ile
   AYNI object'i teyit ediyorsa, o endpoint SAFE/NOT_TESTABLE
   durumunda kalmaya devam edemez — cross_user_status yeniden
   NOT_RUN'a döner ve endpoint yeniden değerlendirmeye alınır (yeni bir
   `target_object` söz konusuysa bunun yerine madde 2 uygulanır).
4. target_owner_confirmed = no iken nihai STATUS asla SAFE
   olarak işaretlenemez — DENIED gibi "erişim engellendi" sonuçları,
   hedeflenen ID'nin gerçekte var olmayan/rastgele bir ID olması
   ihtimaline karşı kanıt sayılmaz. Bu durumda doğru STATUS, bölüm
   50'deki kaynaklardan biriyle sahiplik doğrulanana kadar
   NOT_TESTABLE'dır. Yalnızca target_owner_confirmed = yes
   olduğunda bir DENIED sonucu gerçek bir "SAFE" (yetki kontrolü
   doğru çalışıyor) kararına dönüşebilir.

   **Önemli — bu madde yalnızca SAFE çıkarımını kısıtlar, ALLOWED/
   PARTIAL_LEAK sonuçlarını değil:** `target_owner_confirmed = no`
   durumu bir `ALLOWED` veya `PARTIAL_LEAK` sonucunu geçersiz kılmaz.
   Çünkü response'ta B'ye ait gerçek veri/PII/owner alanı görülmesi
   (ör. `evidence_fields` doluyken) **kendi başına zaten** ownership'i
   kanıtlar — ayrıca dış bir kaynaktan teyide ihtiyaç yoktur. Bu madde
   yalnızca "erişim engellendi" (DENIED) gibi **negatif** sonuçların
   yanlışlıkla "güvenli" diye yorumlanmasını engellemek içindir; pozitif
   bir kanıt (gerçek B verisi/PII sızması) hiçbir zaman bu gate'e takılıp
   bastırılmaz.

   `BLOCKED` bu kuralın DIŞINDADIR ve target_owner_confirmed'in
   değerinden bağımsız olarak HİÇBİR ZAMAN doğrudan SAFE'e
   dönüşemez — çünkü BLOCKED, uygulamanın object-level bir
   yetkilendirme kararı vermediğini, isteğin WAF/rate-limit
   seviyesinde engellendiğini gösterir (bkz. "WAF/rate-limit
   tepkisi karşısında bütçe ve durma kriteri"). BLOCKED alındığında
   önce baseline (A token + A'nın kendi object'i) tekrar test
   edilmelidir: baseline da BLOCKED ise sonuç NOT_TESTABLE'dır;
   baseline normal dönüyorsa yalnızca cross-user isteği engellenmiş
   demektir ve test, o bütçe kuralındaki aynı ardışık N (3-5) deneme
   sınırı içinde DENIED/ALLOWED/PARTIAL_LEAK gibi gerçek bir sonuca
   ulaşana kadar tekrarlanabilir — bu sınır aşılırsa (retry budget
   tükenirse) BLOCKED durumu kalıcı olarak NOT_TESTABLE'a döner;
   BLOCKED kendi başına ne sonsuza kadar tekrarlanan ne de nihai bir
   STATUS'tur.
5. `baseline_status != PASS` iken, cross-user sonucunun **`DENIED`**
   olması hiçbir zaman `SAFE` çıkarımına temel oluşturamaz — çünkü A
   kendi object'ine bile beklendiği gibi erişemiyorsa, B'nin
   object'ine erişememesi authorization'ın doğru çalıştığını değil,
   genel bir bozukluğu (auth altyapısı arızası, yanlış token, vb.)
   gösteriyor olabilir. Bu durumda doğru STATUS `NOT_TESTABLE`'dır,
   baseline düzelene kadar. **Bu gate de yalnızca SAFE'i kısıtlar:**
   `baseline_status != PASS` iken cross-user sonucu `ALLOWED` veya
   `PARTIAL_LEAK` ise (yani B'ye ait gerçek veri/PII sızmışsa), bu
   pozitif kanıt baseline'ın durumundan bağımsız olarak geçerlidir ve
   CANDIDATE/CONFIRMED değerlendirmesine hiçbir engel olmadan girer —
   gerçek bir veri sızıntısı, ilgisiz bir baseline arızası yüzünden
   asla bastırılmaz.

**`cross_user_status` → `STATUS` geçiş tablosu** (agent'ın yorum
alanını daraltmak için — aşağıdaki koşulların **hepsi** birlikte
sağlanmalı):

| Önkoşullar | cross_user_status | STATUS |
|---|---|---|
| baseline PASS + owner confirmed | DENIED | SAFE |
| baseline != PASS + owner confirmed | DENIED | NOT_TESTABLE (baseline netleşene kadar) |
| owner confirmed + B'nin gerçek verisi/PII'si görüldü | ALLOWED | CANDIDATE → confidence 5 ise CONFIRMED |
| owner confirmed + kısmi sızıntı (ör. 403 body'de B'nin e-postası) | PARTIAL_LEAK | CANDIDATE veya CONFIRMED (bkz. aşağıdaki OBSERVED/CLASS notu) |
| owner confirmed ama evidence_fields yetersiz/belirsiz | INCONCLUSIVE | CANDIDATE (confidence 3 altındaysa raporlanmaz) |
| owner **doğrulanamadı** (target_owner_confirmed=no) | DENIED/INCONCLUSIVE | NOT_TESTABLE |
| owner doğrulanamadı ama ALLOWED/PARTIAL_LEAK (pozitif kanıt) | ALLOWED / PARTIAL_LEAK | CANDIDATE/CONFIRMED — owner gate'i pozitif kanıtı engellemez |
| BLOCKED, retry bütçesi tükenmedi | BLOCKED | (henüz nihai değil — retry) |
| BLOCKED, retry bütçesi tükendi | BLOCKED | NOT_TESTABLE |
| confidence 0-2 | herhangi | raporlanmaz (ne SAFE ne CANDIDATE) |

**`PARTIAL_LEAK` için `OBSERVED`/`CLASS` eşlemesi (bölüm 109 için):**
Bir `cross_user_status: PARTIAL_LEAK` sonucu bölüm 109 formatına
dökülürken şu eşleme kullanılır — `OBSERVED: DENY` (çünkü asıl
protected object/action hâlâ engellendi) ve `CLASS: INFO_LEAK` (asıl
sızıntı, tam object erişimi değil, response'ta açığa çıkan
existence/PII/ownership bilgisidir). Eğer aynı endpoint'te ayrıca tam
bir `ALLOWED` bulgusu da varsa, iki bulgu ayrı satırlar halinde
raporlanır (`OBSERVED: ALLOW / CLASS: IDOR` ve `OBSERVED: DENY / CLASS:
INFO_LEAK`) — biri diğerini gölgelememelidir.
```

Çok sayıda endpoint test edilen kapsamlı bir değerlendirmede, bu kayıtların
tamamı aynı zamanda bölüm 38'deki "bulk impact" ve bölüm 99'daki kategori
kapsamı analizine ham veri sağlar: hangi resource kategorilerinin hiç
`CONFIRMED`/`CANDIDATE` üretmediği (kapsanmadığı) buradan görülebilir.

---

# 38. Severity değerlendirmesi için düşünce çerçevesi

Impact değerlendirilirken:

- hangi object?
- hangi kullanıcı?
- private mı?
- PII içeriyor mu?
- finansal veri mi?
- dosya mı?
- başka tenant mı?
- read mi?
- write mi?
- delete mi?
- privileged action mı?
- bulk impact mümkün mü?
- authentication gerekiyor mu?

gibi faktörlere bak.

Örneğin:

```text
Public object → düşük/bug olmayabilir
Private profile → bilgi ifşası
Private invoice → daha ciddi
Private file → daha ciddi
Modify another user's resource → yüksek
Delete another user's resource → yüksek
Cross-tenant access → ciddi
Admin/privileged resource → çok ciddi olabilir
```

Kesin severity programın politikasına göre belirlenmelidir.

## Business logic / state transition IDOR — impact çarpanı

"Write/action IDOR" (bölüm 9 — GET dışındaki metodlar) yalnızca teknik
bir read/write ayrımı değildir; başkasının object'i üzerinde bir
**business-critical aksiyon veya state transition** tetiklenebiliyorsa
impact çok daha yüksektir:

```text
POST /api/orders/{id}/refund      → başkasının siparişini iade etmek
                                     (finansal impact)
POST /api/auctions/{id}/bid       → başkasının adına teklif vermek
POST /api/contracts/{id}/sign     → başkasının sözleşmesini imzalamak
POST /api/documents/{id}/publish  → draft → published state geçişi
POST /api/orders/{id}/approve     → pending → approved state geçişi
```

Bu tür endpoint'ler test edilirken agent özellikle **state machine
geçişlerine** (draft→published, pending→approved, unpaid→paid gibi geri
alınamaz veya iş süreci açısından kritik geçişlere) odaklanmalıdır;
aynı object üzerindeki basit bir `PUT`/`PATCH` (alan güncelleme) ile bir
state transition endpoint'i aynı severity kategorisinde
değerlendirilmemelidir — ikincisi genellikle daha yüksek impact taşır
çünkü geri alınamaz bir iş sürecini tetikler.

## Bulk impact ölçümü

"Bulk impact mümkün mü?" sorusu somutlaştırılabilir. Bir bulgunun tekil
mi yoksa toplu mu etki ürettiğini değerlendirirken:

```text
- Bulgu tekil bir object mi hedefliyor, yoksa bir liste/aggregation
  endpoint'i mi (ör. /api/users yerine /api/users/222)?
- Export/backup endpoint'i (bkz. bölüm 91) tüm tenant'ın verisini tek
  seferde mi döndürüyor, yoksa tek bir object mi?
- Batch endpoint'i (bkz. bölüm 45) dizideki HER ID için ayrı ayrı
  authorization kontrolü mü yapıyor, yoksa dizinin tamamı tek bir
  kontrolden mi geçiyor? (ikincisi, dizideki tek bir yetkili ID'nin
  diğer yetkisiz ID'leri "yıkayabileceği" anlamına gelir)
- Pagination yok veya `limit`/`page_size` çok yüksek bir değere
  ayarlanabiliyorsa, tek bir istekle kaç kayda erişilebiliyor?
```

Bulk impact'i olan bir bulgu (ör. cross-tenant export ile binlerce
kaydın tek istekte sızması), aynı kök nedene sahip tekil bir bulgudan
(tek bir object'e erişim) çok daha yüksek severity ile
değerlendirilmelidir — kök neden aynı olsa da etki alanı farklıdır.

---

# 39. Agent'in her request için sorması gereken sorular

Her API request'i için:

```text
1. Bu request bir object/reference taşıyor mu?
2. Object reference nerede?
   - path
   - query
   - JSON
   - GraphQL
   - header
   - cookie
   - WebSocket
3. Object owner kim?
4. Authenticated user kim?
5. Tenant/organization kim?
6. Parent-child ilişkisi var mı?
7. Birden fazla ID var mı?
8. Frontend hangi ID'yi doğruluyor?
9. Backend hangi ID ile lookup yapıyor?
10. Downstream service hangi ID'yi kullanıyor?
11. GET dışında action var mı?
12. Aynı object'e alternate endpoint var mı?
13. v1/v2 farkı var mı?
14. UUID/opaque reference var mı?
15. Encoding/canonicalization katmanı var mı?
16. Authorization response gerçekten resource'u içeriyor mu?
17. Cross-user A→B testi yapılabilir mi?
18. Reverse B→A testi yapılabilir mi?
19. Unauthenticated/invalid-token davranışı nasıl?
20. Sonuç gerçek protected resource erişimi mi?
```

---

# 40. En önemli mental model

IDOR ararken:

```text
"ID'yi değiştirebilir miyim?"
```

sorusundan daha önemli soru:

```text
"Uygulama bu object'in sahibinin kim olduğunu
hangi noktada ve hangi değer üzerinden kontrol ediyor?"
```

olmalıdır.

Bir request'i:

```text
Authentication identity
        ↓
Authorization identity
        ↓
Tenant identity
        ↓
Parent object
        ↓
Child object
        ↓
Target resource
        ↓
Action
```

zinciri olarak düşün.

Her katmanda identity/resource ilişkisinin korunup korunmadığını kontrol et.

---

# 41. En değerli gelişmiş pattern özeti

Aşağıdaki pattern'ler özellikle önceliklidir:

```text
A token + B object
A token + B file
A token + B invoice
A token + B account
A token + B tenant
A token + B nested resource
A token + B GraphQL node
A token + B mutation target
A token + B WebSocket object
A token + B download/export
```

ve:

```text
parent=A, child=B
owner=A, object=B
tenant=A, object=B
user=A, account=B
requester=A, target=B
gateway=A, downstream=B
frontend checks=A, backend uses=B
```

Bu son gruplar klasik numeric IDOR'dan daha zor ve daha değerli authorization
hatalarını ortaya çıkarabilir.

---

# 44. Blind IDOR (yan kanal ile tespit)

Her IDOR response body'de doğrudan victim verisini dönmez. Bazı durumlarda
tek gösterge:

```text
status code farkı
response time farkı
response length farkı
error message farkı
rate-limit/throttle davranışı farkı
```

olabilir.

Örnek:

```text
GET /api/orders/{mine}      → 200, 42ms
GET /api/orders/{victim}    → 200, 312ms   (ör. ek DB join/log tetikleniyor)
```

veya:

```text
GET /api/tickets/{mevcut-olmayan}  → 404 "Not found"
GET /api/tickets/{victim, erişim yok} → 403 "Forbidden"
```

Eğer "mevcut değil" ile "var ama yetkisiz" farklı response veriyorsa, bu
object varlığının enumerate edilebildiğini gösterir (bilgi sızıntısı) ve
tam BOLA'ya götüren zincirin bir parçası olabilir.

Blind IDOR'da kanıt standardı yine geçerlidir: yalnızca zamanlama/uzunluk
farkı tek başına bulgu değildir, ancak sistematik ve tekrarlanabilir bir
side-channel farkı destekleyici kanıt olarak kaydedilebilir.

**5xx response'lar (500/502/503) için:** Bir 5xx yanıtı tek başına ne
`ALLOW` ne `DENY` kanıtıdır — sunucu hatası authorization kararından
bağımsız olabilir (`cross_user_status=INCONCLUSIVE`). Ancak eğer **kesinlikle
var olmayan** bir ID (`404`) ile **var olduğu bilinen ama erişim
denenen** bir ID arasında tutarlı ve tekrarlanabilir bir `5xx` farkı
gözlemleniyorsa (ör. `GET /orders/999999999 → 404` ama `GET
/orders/{victim} → 500` her seferinde), bu yukarıdaki 403/404
örneğiyle aynı mantıkla bir object-existence side-channel'ıdır —
`CLASS: INFO_LEAK` olarak, aynı tekrarlanabilirlik şartıyla
değerlendirilir. Tek bir `500` gözlemi (tekrarlanabilirlik
doğrulanmadan) her zaman `INCONCLUSIVE` kalır.

---
