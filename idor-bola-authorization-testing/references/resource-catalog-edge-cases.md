# 51. Magic link / şifre sıfırlama / e-posta değiştirme akışlarında IDOR

Bu akışlar genellikle bir token + bir identifier taşır:

```text
/reset-password?token=abc123&user_id=111
/verify-email?token=xyz&account_id=222
/magic-login?token=...&uid=333
```

Test soruları:

```text
token, user_id/account_id/uid ile kriptografik olarak bağlı mı,
yoksa token tek başına mı doğrulanıyor?
token geçerliyken user_id/account_id değiştirildiğinde
   başka bir hesabın reset/verify akışı tetiklenebiliyor mu?
token'ın hangi hesaba ait olduğu server-side saklanan state'ten mi,
   yoksa client'ın gönderdiği parametreden mi belirleniyor?
```

Eğer token geçerliliği yalnızca "var mı/süresi geçmiş mi" ile kontrol edilip
hangi hesaba ait olduğu client-controlled parametreden okunuyorsa, bu ciddi
bir account-takeover potansiyeli taşıyan object-level authorization
hatasıdır ve ayrıca yüksek severity ile değerlendirilmelidir.

---

# 52. Dosya upload / overwrite IDOR

Upload sonrası dosya erişim yolu tahmin edilebilir veya client tarafından
kontrol edilebilirse, başka bir kullanıcının dosyasının üzerine yazılabilir
ya da onun dosya alanına erişilebilir:

```http
PUT /api/upload/{user_id}/{filename}
```

veya:

```json
{
  "upload_path": "users/111/avatar.png"
}
```

Test edilecekler:

```text
path/filename client tarafından belirleniyor mu?
başka bir kullanıcının klasör/namespace'ine yazılabiliyor mu?
mevcut bir dosyanın üzerine yazma (overwrite) engelleniyor mu?
upload sonrası dönen storage/CDN URL'i tahmin edilebilir mi
   ve object-level authorization olmadan erişilebiliyor mu?
```

---

# 53. Pagination / cursor token'larında gömülü object reference

Bazı API'lerde `next_cursor` veya `page_token` değerleri encode edilmiş
filtre/owner/tenant bilgisi taşıyabilir:

```text
cursor = base64({"tenant_id": 111, "offset": 20})
```

Bu değer decode edilip `tenant_id` değiştirilerek tekrar encode edildiğinde
başka bir tenant'ın listesi dönebiliyorsa, bu klasik IDOR'un pagination
bağlamındaki bir varyasyonudur. Aynı mantık `filter`, `sort`, `query` gibi
opak görünümlü state taşıyan parametreler için de geçerlidir.

---

# 56. Mobil uygulama ve gizli/dokümante edilmemiş endpoint'ler

Mobil API'ler web arayüzünde kullanılmayan ek endpoint veya parametre
içerebilir (ör. admin/debug/internal amaçlı ama prod'da aktif kalmış).

Kapsam dahilindeyse:

```text
APK/IPA içinden base URL ve endpoint pattern'lerini çıkar
mobil-only header/parametreleri incele (X-App-Version, X-Device-ID vb.)
web'de kısıtlı olan bir object endpoint'inin mobil API'de
   aynı kısıtlamaya sahip olup olmadığını doğrula
```

Mobil ve web istemcilerinin aynı backend'i farklı yetkilendirme
varsayımlarıyla çağırması, bölüm 20'deki "alternate endpoint" pattern'inin
istemci-bazlı bir uzantısıdır.

---

# 57. Yardımcı otomasyon araçları (yalnızca doğrulama amaçlı)

Aşağıdaki araçlar object-level authorization farklarını sistematik olarak
gözlemlemeye yardımcı olabilir; bulgu üretmezler, yalnızca A/B karşılaştırmasını
hızlandırırlar:

```text
Burp Suite — Autorize eklentisi (düşük yetkili session ile
   yüksek yetkili request'leri tekrar oynatıp response farkını raporlar)
Burp Suite — Auth Analyzer
Burp Suite — Match/Replace (token/ID swap otomasyonu)
Burp Suite — Turbo Intruder (race condition testleri için, bkz. bölüm 48)
```

Bu araçların ürettiği her "fark" bölüm 37'deki dört parçalı kanıt standardına
göre doğrulanmadan bulgu olarak raporlanmamalıdır.

---

# 58. Genişletilmiş checklist eki

Bölüm 39'daki soru listesine ek olarak, agent şunları da değerlendirmelidir:

```text
21. Bu endpoint bir batch/bulk işlem mi? Dizideki her ID ayrı doğrulanıyor mu?
22. Request body'de beklenmedik ownership/ilişki alanı (owner_id, tenant_id,
    account_id) kabul ediliyor mu? (mass assignment)
23. Aynı parametre birden fazla kez gönderildiğinde davranış değişiyor mu? (HPP)
24. Object-level işlem race-safe mi? Paralel request'ler farklı sonuç veriyor mu?
25. Bu response CDN/proxy/app cache tarafından identity'den bağımsız
    cache'leniyor olabilir mi?
26. Başka bir endpoint'in response'unda görünen bir ID/token bu endpoint'te
    authorization'ı bypass etmek için kullanılabilir mi? (second-order)
27. Magic link/reset/verify token'ı, taşıdığı user/account ID'den bağımsız
    olarak mı doğrulanıyor?
28. Upload/overwrite path'i client tarafından kontrol edilebiliyor mu?
29. Pagination/cursor/filter token'ı decode edilebilir owner/tenant bilgisi
    taşıyor mu?
30. Content-Type değiştirildiğinde authorization middleware hâlâ devrede mi?
31. Proxy/WAF seviyesinde bir path kısıtlaması varsa, `X-Original-URL` /
    `X-Rewrite-URL` gibi header'larla veya path-encoding varyantlarıyla
    (`;`, `%2e`, çift slash, trailing slash) bu kısıtlama atlanabiliyor mu?
    (bkz. bölüm 61)
32. Authorization kararı `X-Forwarded-For` / `X-Real-IP` gibi client-controlled
    bir IP header'ına dayanıyor mu? (internal-network whitelist bypass)
```

---

# 91. Export / Backup / Snapshot Endpoint'lerinde IDOR

```http
GET /api/users/111/export
GET /api/accounts/111/backup
GET /api/projects/111/snapshot
```

Export endpoint'leri genellikle daha fazla veri döndürür ve farklı authorization mantığı kullanabilir. Ayrıca export dosyasındaki internal ID'ler başka attack vector'ları için kullanılabilir.

---

# 92. Search / Filter Endpoint'lerinde IDOR

```http
GET /api/search?q=*&owner_id=111
GET /api/search?q=*&filter[owner]=111
GET /api/search?q=*&where[user_id]=111
```

Search endpoint'lerinde filter parametreleri manipüle edilerek başka kullanıcının object'leri listelenebilir. Elasticsearch, MongoDB, SQL backend'lerde filter injection ile birleşebilir.

---

# 93. Aggregation / Analytics Endpoint'lerinde IDOR

```http
GET /api/analytics?user_id=111&metric=total_spend
GET /api/dashboard?account_id=111&period=monthly
```

Analytics endpoint'leri genellikle toplu veri döndürür ve farklı authorization mantığı kullanabilir. `user_id`, `account_id`, `tenant_id` gibi parametreler manipüle edilebilir.

---

# 94. Notification / Email / SMS Template IDOR

```http
GET /api/notifications/111/preview
GET /api/emails/111/render
GET /api/sms/111/content
```

Notification template'lerinde object reference manipülasyonu ile başka kullanıcının notification içeriği görüntülenebilir.

---

# 95. Audit Log / Activity Stream IDOR

```http
GET /api/audit?user_id=111
GET /api/activity?actor_id=111
```

Audit log endpoint'leri genellikle daha fazla detay içerir ve farklı authorization mantığı kullanabilir.

---

# 96. Import / Bulk Upload Sonrası Object Assignment IDOR

```http
POST /api/import/csv
{
  "file_id": "uploaded_123",
  "target_account_id": "222"
}
```

Import işlemi sonrası object'lerin hangi account'a atandığı client-controlled ise, başka kullanıcının account'una object inject edilebilir.

---

# 97. Shared Link / Magic Link / Invite Token IDOR

```http
GET /api/share/TOKEN?resource_id=111
GET /api/invite/TOKEN?project_id=222
```

Shared link token'ları genellikle belirli resource'lar için geçerlidir. Eğer token resource ID'den bağımsız olarak doğrulanıyorsa veya resource_id parametresi değiştirilebiliyorsa, BOLA oluşur.

---

# 98. Comment / Review / Rating IDOR

```http
PUT /api/reviews/222
DELETE /api/comments/222
```

Kullanıcı sadece kendi yorumunu/review'sini düzenleyebilmelidir. Başkasının yorumunu değiştirebiliyorsa write IDOR vardır.

---

# 99. Kapsamlı endpoint/resource kategori referans listesi

Yukarıdaki bölümlerde anlatılan test metodolojisi (bkz. bölüm 8 "REST API'de
sistematik test", bölüm 31 "Authorization matrix", bölüm 37 "Bulguyu
doğrulama standardı") **her resource tipi için aynı şekilde** uygulanır:

```text
1. Baseline    : A token + A object → beklenen: allow
2. Cross-user  : A token + B object → beklenen: deny (403/404)
3. Reverse     : B token + A object → beklenen: deny
4. Method sweep: GET/PUT/PATCH/DELETE/POST-action için tekrarla
5. Kanıt       : response gerçekten B'nin protected verisini/aksiyonunu içeriyor mu?
```

Genel şablon:

```http
GET    /api/{resource}/{id}
PUT    /api/{resource}/{id}
DELETE /api/{resource}/{id}
POST   /api/{resource}/{id}/{action}
```

Aşağıdaki liste, bir API yüzeyini tararken object-level authorization
açısından akla gelmesi gereken resource/domain isimlerini kategori bazında
toplar. Amaç her biri için ayrı bir bölüm yazmak değil — hepsi yukarıdaki
tek şablonla test edilir — amaç recon sırasında "bu isimde bir endpoint
görürsem IDOR ihtimalini değerlendiririm" listesini elde bulundurmaktır.
Agent, kapsam içindeki gerçek endpoint isimlerine göre bu listeden ilgili
kategorileri seçip uygulamalıdır; listedeki her kelime için ayrı test
raporu üretmek gerekmez.

## Önceliklendirme

200+ kategorinin tamamı eşit önemde değildir. Zaman/istek bütçesi
kısıtlıysa (bkz. bölüm 35 "otomatik aday çıkarma"), aşağıdaki sıralama
önerilir — üsttekiler genellikle daha yüksek finansal/PII impact taşır
ve gerçek dünya bug bounty programlarında daha sık ödüllendirilir:

```text
Yüksek öncelik : payment, invoice, order, user, account, file, message,
                 wallet, transaction, address, document
Orta öncelik   : report, audit, notification, webhook, export, booking,
                 subscription, contract, ticket
Düşük öncelik  : badge, skin, theme, recipe, workout, playlist, avatar
```

Bu sıralama katı bir kural değildir — hedefin iş modeline göre
değişebilir (ör. bir oyun platformunda "skin/item" yüksek öncelikli
olabilir). Amaç, agent'ın kısıtlı bir bütçede önce en yüksek etkili
kategorilere odaklanmasıdır.

**İpucu — hedefin iş modelini nasıl anlarım:** Hedefin ana sayfası,
pricing/fiyatlandırma sayfası veya API dokümantasyonundaki resource
isimleri, önceliklendirmede ek ağırlık taşımalıdır. Örneğin pricing
sayfasında "Pro Plan'da unlimited projects" görülüyorsa `project`
resource'u o hedef için yüksek öncelikli demektir; "free tier'da 3
workspace" görülüyorsa `workspace` muhtemelen tenant-isolation
açısından kritik bir resource'dur. Genel öncelik listesi bir başlangıç
noktasıdır; hedefe özgü sinyaller bu sıralamayı geçersiz kılabilir.

**Ticaret / ödeme / finans:** payment, transaction, wallet, balance,
account, invoice, receipt, statement, refund, charge, transfer, wire,
remittance, currency, coin, token, cart, basket, checkout, order,
purchase, pricing, rate, fee, discount, rebate, allowance, sale,
promotion, tax, duty, tariff, coupon, voucher, promo code, gift, reward,
point, loan, credit, mortgage, investment, portfolio, fund, insurance,
policy, claim.

**Envanter / e-ticaret operasyonları:** product, item, SKU, category,
collection, line, brand, manufacturer, supplier, vendor, partner,
inventory, stock, warehouse, depot, storage, supply, shipping, delivery,
tracking, courier, logistics, return, exchange, package, parcel,
shipment.

**Hukuk / uyum / güvenlik yönetimi:** risk, compliance, audit, governance,
regulation, standard, contract, agreement, terms, legal, litigation,
dispute, intellectual property, patent, trademark, license, permit,
authorization, certificate, accreditation, certification, security,
threat, vulnerability, incident, breach, forensic, evidence,
investigation, recovery, backup, restore, disaster recovery, business
continuity, crisis.

**CRM / satış / pazarlama:** customer, client, contact, lead, opportunity,
deal, campaign, ad, creative, channel, source, medium, segment, audience,
persona, journey, funnel, flow, experiment, variant, A/B test, feature
flag, toggle.

**DevOps / platform / altyapı:** release, deployment, build, environment,
namespace, cluster, secret, credential, certificate, policy, rule,
condition, workflow, automation, trigger, connector, adapter, plugin,
extension, add-on, log, debug, trace, metric, health, status, migration,
import, export, sync, replication, mirror, cache, index, search, queue,
job, task, worker, processor, handler, pipeline, stage, step, filter,
sort, group, view, configuration, setting, parameter, template,
blueprint, schema, widget, component, module, theme, skin, style.

**AI / analitik / raporlama:** bot, agent, assistant, model, dataset,
training, prediction, inference, result, report, analytics, dashboard,
visualization.

**Form / eğitim / İK / organizasyon:** feedback, review, rating, survey,
form, questionnaire, response, answer, submission, quiz, exam,
assessment, badge, achievement, enrollment, registration, application,
attendance, participation, engagement, schedule, timetable, agenda,
reservation, booking, appointment, team, group, role, permission, ACL,
setting, preference, profile, notification, alert, reminder,
subscription, plan, billing, task, todo, note, memo, draft, integration,
webhook, API key.

**İletişim / sosyal / içerik:** message, communication, conversation,
chat, channel, room, call, meeting, conference, recording, transcript,
summary, annotation, comment, reply, thread, bookmark, favorite, save,
tag, label, list, set, folder, directory, path, file, document,
attachment, media, image, video, audio, music, podcast, stream,
broadcast, live, playlist, episode, chapter, season, series, genre,
recommendation, suggestion, trend, popular, featured, feed, timeline,
activity, story, post, article, like, upvote, share, repost, crosspost,
follow, subscribe, unsubscribe, block, mute, report, invite, request,
join, leave, exit, ban, kick, remove.

**Web / routing:** page, site, domain, route, path, URL, redirect,
forward, proxy, shortlink, alias, slug.

**IoT / konum / fiziksel dünya:** QR, barcode, RFID, NFC, bluetooth,
beacon, sensor, device, firmware, driver, hardware, component, vehicle,
fleet, asset, trip, journey, location, GPS, coordinate, map, layer, tile,
geofence, zone, region, weather, energy, utility, water, gas,
electricity, waste, recycling, agriculture, crop, livestock, animal.

**Sağlık / yaşam tarzı:** food, recipe, ingredient, nutrition, diet,
fitness, exercise, workout.

**Spor / etkinlik / mekân:** sport, game, match, league, tournament,
championship, player, roster, score, stat, standing, ticket, pass,
admission, venue, stadium, arena, seat, section, row, show, performance,
artist, performer, album, track, song, concert, gig, festival, place,
resource, equipment, facility, room, space, service, offering, package.

**Seyahat / ulaşım:** tour, travel, hotel, accommodation, stay, flight,
airline, airport, train, railway, station, bus, coach, terminal, car
rental, ride, bike, scooter, boat, ship, cruise.

**Oyunlaştırma / oyun içi ekonomi:** membership, tier, level, rank,
leaderboard, scoreboard, ranking, challenge, quest, mission, stage,
character, avatar, skin, weapon, equipment, ability, power, objective,
loot, drop.

**Genel CRUD/aksiyon fiilleri (herhangi bir resource ile birleşebilir):**
create, read, update, delete, promote, demote, merge, split, combine,
clone, copy, duplicate, move, relocate, archive, unarchive, purge,
erase, undelete, recover.

---

# 101. Admin / Destek Ekibi "Impersonate User" (Kullanıcı Olarak Giriş) Özellikleri

Birçok B2B/SaaS uygulamasında destek ekibinin sorun gidermek için "bu
kullanıcı olarak görüntüle/giriş yap" özelliği bulunur:

```http
POST /api/admin/impersonate
Authorization: Bearer SUPPORT_TOKEN

{
  "target_user_id": "1002"
}
```

Bu özellik object-level authorization açısından iki ayrı risk taşır:

```text
1. Yetki seviyesi kontrolü: impersonate endpoint'i gerçekten
   support/admin rolü gerektiriyor mu, yoksa normal bir authenticated
   kullanıcı da target_user_id değiştirerek başkası olarak "giriş
   yapabiliyor" mu? (bu durumda BFLA + IDOR birleşik bir bulgu olur)
2. Kapsam sınırı: impersonate edilen oturum, hedef kullanıcının YALNIZCA
   destek senaryosunda gerekli olan verilerine mi erişebiliyor, yoksa
   ödeme yöntemi ekleme/şifre değiştirme/API key oluşturma gibi
   hassas action'ları da mı yapabiliyor? (aşırı geniş impersonation scope)
3. Audit/iz bırakma: impersonate edilen oturumla yapılan işlemler
   loglanıyor mu, yoksa hedef kullanıcı adına "sessizce" işlem
   yapılabiliyor mu? (doğrudan IDOR değil ama bulgunun etkisini
   büyüten bir faktördür)
4. Impersonation token'ının ömrü ve scope'u: normal login token'ından
   ayrılabiliyor mu (ör. `X-Impersonate-User`, `X-Acting-User` gibi
   header'lar — bkz. bölüm 10), yoksa aynı JWT üzerinde `sub` claim'i mi
   değiştiriliyor?
```

İlişkili header isimleri için bölüm 10'daki "X-Acting-User",
"X-Impersonate-User" listesine bakılabilir; buradaki fark, bu header'ların
**meşru bir özelliğin parçası olarak zaten var olduğu** ve testin amacının
header'ın varlığını keşfetmek değil, kimin bu özelliği tetikleyebildiğini
ve ne kadar geniş erişim verdiğini doğrulamak olduğudur.

---

# 102. Soft-Delete / Trash / Geri Dönüşüm Kutusu Endpoint'lerinde IDOR

Bir çok uygulama "silme" işlemini gerçek DELETE yerine soft-delete
(`deleted_at`, `is_deleted=true`) ile yapar ve silinen öğeleri ayrı bir
trash/recycle-bin görünümünde listeler:

```http
GET  /api/trash
GET  /api/trash/1002
POST /api/trash/1002/restore
DELETE /api/trash/1002/permanent
```

Bu endpoint'ler genellikle ana resource endpoint'inden **sonra** eklenir ve
ana endpoint'te uygulanan object-level authorization middleware'i trash
route'larına kopyalanmamış olabilir. Test edilmesi gerekenler:

```text
1. /api/trash listesi yalnızca authenticated kullanıcının kendi
   sildiği öğeleri mi gösteriyor, yoksa tüm kullanıcıların/tenant'ların
   silinmiş öğelerini mi?
2. Başka bir kullanıcının silinmiş öğesi restore edilebiliyor mu?
   (A token + B'nin trash'teki object'i → restore → B'nin verisi A'nın
   hesabında ortaya çıkar mı?)
3. "Permanent delete" başka kullanıcının trash öğesinde çalışıyor mu?
4. Trash'teki bir öğenin içeriği (önizleme, dosya, meta veri) ana
   endpoint'te engellenen ownership kontrolünden muaf mı?
```

Bu, bölüm 20'deki "alternate endpoint" pattern'inin bir varyasyonudur:
aynı object'e giden ikinci bir yol, farklı (veya eksik) bir authorization
middleware zincirinden geçebilir.

---
