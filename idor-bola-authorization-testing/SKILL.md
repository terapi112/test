---
name: idor-bola-authorization-testing
description: >
  Sistematik IDOR/BOLA ve object-level authorization testi için kapsamlı metodoloji.
  REST, JSON, GraphQL, cookies, custom headers, UUID/hash/base64 referansları,
  nested resources, multi-tenant uygulamalar, microservice/gateway ayrışmaları,
  WebSocket, JWT doğrulama davranışları, batch/mass-assignment/race-condition/cache
  kesişimleri ve 200+ resource kategorisi için hazır kontrol listesi içerir.
  Yalnızca açıkça yetkilendirilmiş bug bounty/pentest hedeflerinde kullanılmalıdır.
---

# IDOR / BOLA / Object-Level Authorization Testing Skill

## 0. Amaç ve temel ilke

Bu skill'in amacı, bir uygulamanın kullanıcıya ait bir object/resource üzerinde
yetki kontrolünü doğru yapıp yapmadığını sistematik biçimde test etmektir.

**IDOR (Insecure Direct Object Reference)** geleneksel isimdir.
Modern API güvenlik terminolojisinde aynı temel sınıf çoğunlukla
**BOLA (Broken Object Level Authorization)** olarak ifade edilir.

En önemli kural:

> Bir ID'nin değiştirilebilmesi tek başına IDOR değildir.
> Bulguyu oluşturan şey, bir kullanıcının başka bir kullanıcının korumalı
> object/resource'una yetkisi olmadan erişebilmesi, değiştirebilmesi veya
> bir action uygulayabilmesidir.

Temel kanıt modeli:

```text
Attacker's valid session
        +
Victim's object/resource reference
        ↓
Victim'in korumalı kaynağına yetkisiz erişim/değişiklik/action
        ↓
IDOR / BOLA / authorization failure
```

**Numaralandırma notu:** Bölüm numaraları 1'den 109'a kadar gider ama
43 ve 59 kasıtlı olarak boştur — 43 numaralı içerik "Sonuç" bölümü olarak
109'a taşınmıştır, 59 ise skill'in düzenlenme sürecinde kalan bir
meta-not olduğu için çıkarılmıştır. Bu, içerikte eksiklik anlamına
gelmez; dosyadaki tüm "bkz. bölüm X" referansları doğrulanmıştır.

---

# Katman Haritası ve Signal-Driven Test Stratejisi (Agent için okuma rehberi)

Bu bölüm numaralandırılmış bölüm sırasının bir parçası değildir; mevcut
1-109 numaralı bölümleri **nasıl okumak/uygulamak gerektiğini** anlatan bir
navigasyon rehberidir. Sayısal numaralandırma korunmuştur (böylece
dosyadaki "bkz. bölüm X" referansları geçerliliğini korur); burada yalnızca
bu bölümlerin hangi kavramsal katmana ait olduğu gösterilir.

## Neden bu harita gerekli

Bu skill, çekirdek IDOR/BOLA testinin yanında, object-level authorization
sınırını **farklı bir katmandan** etkileyebilecek komşu teknik sınıflarını
da içerir: DNS rebinding, request smuggling, CORS misconfiguration, SAML
assertion manipülasyonu, WAF/CDN bypass gibi. Bunların hiçbiri kendi
başına "IDOR" değildir — SSRF, HTTP desync, federasyon/authentication veya
ağ erişimi sınıflarına daha yakındır. Ancak pratikte bu teknikler sıklıkla
object-level authorization'ı atlatmanın **ön koşulu veya zincirin bir
halkası** olur (ör. WAF atlatılmadan admin endpoint'ine hiç ulaşılamaz).
Bu yüzden dosyadan çıkarılmadılar, ama aşağıdaki katmanlarla açıkça
etiketlendiler ki agent "bu bir IDOR skill'i" ile "burada her güvenlik
bypass'ı var" algısını karıştırmasın.

## 5 katman modeli

```text
Layer 1 — Core IDOR
  Bölüm 1-17: path, query, JSON, GraphQL temel, header/cookie identity,
  file/download, UUID/opaque identifier

Layer 2 — Relationship Confusion
  Bölüm 5-7, 18-20, 30, 41, 46, 50: multiple ID, parent/child,
  owner/object mismatch, tenant/object mismatch, frontend/backend
  mismatch, gateway/downstream mismatch, second-order reference

Layer 3 — Alternate Protocol / Architecture
  Bölüm 12, 22, 45, 69-73, 85-90, 100, 103: GraphQL ileri teknikler,
  WebSocket, SSE, batch/bulk, gRPC, serverless, service mesh,
  federation, webhook, presigned URL, pub/sub

Layer 4 — Parser / Normalization
  Bölüm 15-17, 47, 54-55, 63-67, 67a-67b: Base64/encoding,
  canonicalization, HPP, JPP, content-type, case/Unicode, path
  normalization, double encoding, header casing

Layer 5 — Advanced Authorization Boundary (komşu sınıflar)
  Bölüm 23-28, 42, 60-62, 68, 74-84, 88, 91, 101-102, 104-108:
  JWT/OAuth/OIDC/SAML, path traversal, method override, CORS,
  request smuggling, DNS rebinding, open redirect, WAF/CDN/Host
  bypass, impersonation, export endpoint'leri

  NOT: Bu katmandaki DNS rebinding (79), CORS (81), SAML (75),
  request smuggling (78) gibi bölümler kendi başlarına ayrı zafiyet
  sınıflarıdır (sırasıyla SSRF/network, tarayıcı-kaynaklı erişim,
  authentication/federasyon, HTTP desync). Burada yer almalarının tek
  sebebi, object-level authorization sınırını dolaylı olarak
  etkileyebilmeleridir; bu skill onları kendi başına derinlemesine
  öğretmez, yalnızca IDOR/BOLA ile kesiştikleri noktayı işaretler.
```

## Signal-driven test stratejisi

**Agent, bir endpoint'e 109 bölümün tamamını körlemesine uygulamamalıdır.**
Bu hem gereksiz yüzlerce request üretir hem de false-positive oranını
artırır. Doğru akış şudur:

```text
Endpoint/istek keşfedildi
        ↓
HER ZAMAN çalıştır: Layer 1 (Core IDOR) + Layer 2 (Relationship Confusion)
        ↓
Aşağıdaki sinyallerden hangisi varsa, YALNIZCA o alt-aile eklenir:

  GraphQL endpoint'i (/graphql, query/mutation body)
        → Layer 3 GraphQL ailesi: bölüm 12, 69, 70, 71, 85, 89

  WebSocket/SSE bağlantısı
        → Layer 3 realtime ailesi: bölüm 22, 72, 73, 103

  JWT kullanılıyor (Authorization: Bearer <JWT>)
        → Layer 5 JWT ailesi: bölüm 23-28, 42

  OAuth/OIDC/SAML login akışı gözlemlendi
        → Layer 5 federasyon ailesi: bölüm 74, 75, 80

  Microservice/API gateway mimarisi belirtileri (farklı response
  formatları, X-Service-* header'ları, internal endpoint sızıntısı)
        → Layer 2/5 gateway ailesi: bölüm 18, 78, 88

  Presigned/signed URL response'da görüldü (S3/GCS/Azure imzalı link)
        → Layer 3: bölüm 100

  Admin/destek paneli veya "login as user" özelliği fark edildi
        → Layer 5: bölüm 101

  Trash/recycle-bin/soft-delete endpoint'i fark edildi
        → Layer 5: bölüm 102

  Batch/bulk endpoint'i fark edildi (dizide birden fazla ID)
        → Layer 3: bölüm 45

  Response header/body'de CDN/WAF izleri var (Cloudflare, Akamai vb.
  header'ları) VEYA bir path'te 403 alındı ve bunun proxy/WAF
  seviyesinde olduğuna dair belirti var
        → Layer 4 + Layer 5 bypass aileleri: bölüm 61, 65-67, 67a-67b,
          105-108 (bkz. aşağıdaki "403/401 bypass ne zaman denenir" notu)

  Aynı endpoint'e birden fazla content-type ile istek atılabiliyor
        → Layer 4: bölüm 55, 63

  Cache-Control/CDN cache davranışı şüpheli
        → bölüm 49, 106

  GraphQL şemasında/introspection'da `node(id: ID!)` veya `nodes(ids: [ID!])`
  query'si (Relay/Global Object Identifier pattern) fark edildi
        → Layer 3 GraphQL ailesi + bölüm 12'ye ek: B'nin object'ine ait
          opaque/Base64 global ID (tipik biçim `TypeName:internal_id`)
          elde edilip `query { node(id: "B_GLOBAL_ID") { ... on X { ... } } }`
          şeklinde doğrudan sorgulanmalı; tip-spesifik alan adı bulmaya
          gerek kalmadan tek bir global resolver üzerinden çok sayıda
          object tipine erişim denenebileceği için bu, standart
          `query { user(id) }` testinden ayrı ele alınmalıdır.

  A token + B'ye ait object ID ile istek atıldı VE cevap 200 OK ama
  dönen veri boş `[]`/`null` VEYA yalnızca A'nın kendi object'lerini
  içeriyor
        → Bu bir "eksik authorization" sinyali DEĞİL, tam tersi bir
          sinyaldir: Implicit Scope Enforcement / Auto-Filtering.
          Aksiyon: Bu endpoint'te aynı obje/ID için ek varyasyon
          (encoding, HPP, alternate ID formatı vb.) denemeden önce,
          önce bu davranışın gerçekten tutarlı olduğunu 1-2 farklı
          B object'i ile doğrula; tutarlıysa bu endpoint'i "korumalı"
          olarak işaretle ve gereksiz request harcamayı durdur. (Bkz.
          bölüm 37 semantic diff — "array length" ve "boş liste" kontrolü
          burada agent'ın DURMASI için de kullanılır, yalnızca bulgu
          tespiti için değil.)
```

### Sinyal kaçırma riski

Sinyal-güdümlü strateji, bilinen pattern'lere (`/graphql` path'i,
`Upgrade: websocket` header'ı vb.) dayanır. Ama bir sinyal her zaman
standart biçimde görünmeyebilir — ör. GraphQL endpoint'i `/api` altında
sunuluyor olabilir (`/graphql` değil), WebSocket bağlantısı `wss://`
üzerinden HTTP history'de görünmeyebilir, ya da GraphQL yerine
GraphQL-benzeri özel bir RPC formatı kullanılıyor olabilir. Bu durumda
sinyal "yok" değil, **kaçırılmıştır** — ve agent Layer 1+2 dışına hiç
çıkmayabilir.

Bunu azaltmak için FAZ 1 (recon) sırasında agent yalnızca URL pattern'ine
güvenmemeli, response'un Content-Type'ını, body yapısını (ör. `{"data":
..., "errors": ...}` GraphQL'e işaret eder) ve varsa API
dokümantasyonunu (bkz. bölüm 50 "Object Reference Acquisition" madde 12)
aktif olarak incelemelidir. Şüpheli ama kesin olmayan bir sinyal
durumunda, ilgili katman **düşük öncelikli** olarak yine de test
kapsamına dahil edilebilir; sinyal yokluğunu "bu katman kesinlikle
yok" diye yorumlamak yanlış negatif riskini artırır.

### 403/401 bypass teknikleri ne zaman denenir?

Bölüm 61, 65-67, 67a-67b, 105-108'deki header/path/encoding listeleri birer
**payload sözlüğüdür**, "her authorization endpoint'inde hepsini dene"
talimatı değildir. Doğru mantık:

```text
403/401 alındı
        ↓
Bu bir object-level authorization kararı mı (bkz. Layer 1/2 testleri),
yoksa bir path/route seviyesinde erişim kısıtlaması mı? (endpoint'in
tamamı, obje ID'sinden bağımsız olarak engelli mi?)
        ↓
Path/route seviyesinde kısıtlama şüphesi VARSA:
        ↓
   Uygulamada bir proxy/CDN/WAF katmanı olduğuna dair sinyal var mı?
   (response header'ları, farklı Host ile farklı davranış, dokümante
   edilmemiş ama recon'da bulunan bir path)
        ↓
   EVET → önce en yüksek etkili teknikten başla: Host header varyantları
          (bölüm 105) → path normalization ailesi (bölüm 65-67) →
          header injection (bölüm 61) → WAF fail-open (bölüm 107)
   HAYIR → bu muhtemelen application-level bir authorization kararıdır,
          bypass listesi yerine Layer 1/2 object-level testlerine
          odaklan
```

### WAF/rate-limit tepkisi karşısında bütçe ve durma kriteri

Bölüm 105-108'deki bypass payload'ları arka arkaya denenirken hedefin
`429 Too Many Requests` veya WAF/CDN kaynaklı bir engelleme
(`403`/`503`, genelde farklı bir body/header imzasıyla gelir) döndürmeye
başlaması olası bir durumdur. Bunu fark etmeden devam etmek, agent'ın
kendi ürettiği engellenmeyi "sistem güvenli, hepsi 403 alıyor" diye
yanlış yorumlamasına (false negative) yol açar. Kural:

```text
Ardışık N (örn. 3-5) denemede 429 VEYA WAF-imzalı 403/503 alındıysa:
        ↓
1. Dur ve baseline'ı (Layer 1: geçerli A token + A'nın kendi object'i)
   TEKRAR test et.
        ↓
   Baseline da engelleniyorsa → bu IDOR sonucu değil, rate-limit/WAF
   engelidir; bu endpoint'teki bypass denemeleri bu oturum için
   geçersiz sayılmalı, sonuç "NOT_TESTABLE" olarak işaretlenmeli
   (bkz. bölüm 109 "Agent output contract" STATUS alanı).
        ↓
   Baseline normal dönüyorsa → yalnızca bypass payload'ları
   engelleniyor; payload sıklığı düşürülüp (request arası bekleme,
   daha az varyant) devam edilebilir, ancak tüm 105-108 listesini
   art arda denemek yerine en yüksek olasılıklı 2-3 teknikle
   sınırlanmalıdır.
```

Her header/path varyantı denendikten sonra, yalnızca **gerçekten korunan
kaynağın içeriğini/aksiyonunu döndürdüğü** doğrulanan sonuçlar bulgu
olarak işaretlenmelidir (bkz. bölüm 37 kanıt standardı) — status code
değişimi tek başına yeterli değildir.

## Uçtan uca çalışma sırası (execution fazları)

Yukarıdaki "hangi sinyalde hangi bölüm ailesi" mantığı, tek bir endpoint
için hangi teknik ailesinin devreye gireceğini anlatır. Bu ayrıca, bir
hedefe **baştan sona** nasıl yaklaşılacağını anlatan sıralı bir akıştır —
ikisi birbirini tamamlar:

```text
FAZ 0 — Scope/yetki doğrulama
  Hedef açıkça yetkilendirilmiş mi? (bkz. bölüm 109 Güvenlik sınırı)

FAZ 1 — Recon / endpoint keşfi
  API yüzeyi haritalanır (bölüm 32-34 Burp/Katana workflow)

FAZ 2 — Object reference extraction
  Her endpoint'te object reference nerede taşınıyor? (bölüm 3, 39)

  NOT — pratikte en sık darboğaz burasıdır: ID'yi bulduktan sonra
  test etmek (FAZ 5) genellikle mekanik bir adımdır; asıl zorluk
  B'nin object referansını hiç bulamamaktır (özellikle GraphQL,
  batch/nested response veya opak token kullanan API'lerde doğrudan
  URL/JSON'da görünmeyebilir). Bu yüzden FAZ 2, tek bir "ID'yi bul"
  adımı değil, bölüm 50 "Object Reference Acquisition" altındaki 12
  kaynağın (ikinci hesabın kendi response'u, shared resource,
  notification/activity feed, list/search, export/download URL,
  GraphQL nested response, WebSocket/SSE broadcast, pagination
  cursor, debug/internal alan sızıntısı, tahmin edilebilir ID,
  API dokümantasyonu sızıntısı) sistematik olarak taranmasını
  gerektiren ayrı bir alt-faz olarak ele alınmalıdır. Bu tarama
  atlanırsa agent'ın kapsadığı authorization mantığı doğru olsa
  bile hiçbir B object'i bulunamadığı için test hiç çalışmayabilir.

FAZ 3 — Identity & ownership mapping
  Kimlik nasıl taşınıyor (token/cookie/header), object'in owner/tenant
  zinciri nedir? (bölüm 5 relationship graph modeli)

FAZ 4 — Baseline
  A token + A object → beklenen davranış doğrulanır (bölüm 8.1)

FAZ 5 — Cross-user authorization testi
  A token + B object, B token + A object (bölüm 8.2-8.3, 31 matrix)
  — B'nin object referansı nereden bulunur: bölüm 50 "Object Reference
  Acquisition"

FAZ 6 — Relationship confusion
  Multiple ID, parent/child, tenant/object, role/object ilişkileri
  (bölüm 5-7, 18-20, 31 role matrix)

FAZ 7 — Signal-driven extension'lar
  Yukarıdaki "Signal-driven test stratejisi"ne göre GraphQL/WebSocket/
  JWT/gateway/presigned URL vb. ailelerden ilgili olanlar eklenir

FAZ 8 — Semantic response verification
  Yalnızca status code değil, ownership evidence extraction (bölüm 37)

FAZ 9 — Impact/severity değerlendirmesi
  Bölüm 38

FAZ 10 — Finding/rapor üretimi
  Bölüm 109'daki "Agent output contract" formatına göre
```

Bu fazlar zorunlu bir checklist değildir — küçük/tekli bir endpoint testi
için FAZ 4-5-8 yeterli olabilir; FAZ 0-3 ve FAZ 9-10 özellikle çok
endpoint'li, tam kapsamlı bir değerlendirmede anlamlıdır.

---

## Detaylı referans dosyaları

Yukarıdaki 5 katmanlı model ve faz sırası, hangi konunun ne zaman devreye
girdiğini gösterir. Her fazın **detaylı teknik içeriği** ayrı referans
dosyalarında tutulur — bu dosyayı şişirmemek için, ilgili faza gelindiğinde
sadece o dosya okunur.

| Dosya | Kapsadığı bölümler | Ne zaman okunmalı |
|---|---|---|
| `references/core-idor-reference-testing.md` | 1–17 | FAZ 1-2: Object reference keşfi — path/query/JSON/GraphQL temel, header/cookie identity, file/download, UUID/opaque, Base64/encoding, canonicalization, hash-like referanslar |
| `references/authorization-architecture-patterns.md` | 18–22, 29–30, 45–46, 48–50, 68 | FAZ 6-7: Multi-service/multi-tenant mismatch, alternate endpoint, method mismatch, WebSocket, en zor pattern'ler, frontend/backend mismatch, batch/mass-assignment, race condition, shared cache, second-order reference, array index |
| `references/jwt-oauth-federation.md` | 23–28, 42, 74–75, 80 | Sinyal JWT/OAuth/SAML gösterdiğinde: JWT signature/config/confusion, authentication bypass ayrımı, güvenli JWT test özeti, OAuth/OIDC, SAML, open redirect ile token çalma |
| `references/evidence-methodology-severity.md` | 31–41, 44 (37a dahil) | FAZ 8-10: Authorization matrix, Burp/Intruder/Katana workflow, aday çıkarma mantığı, false positive filtreleme, kanıt standardı + Evidence Engine (37a), severity çerçevesi, mental model, blind IDOR |
| `references/parser-normalization-and-bypass.md` | 47, 54–55, 60–67 (67a-67b dahil) | Sinyal encoding/parser/normalization farkı gösterdiğinde: HPP, NoSQL/ORM query operator injection, content-type bypass, path traversal, header injection, method override, JPP, API key format, case/Unicode, trailing slash, double encoding, protokol downgrade, header casing |
| `references/waf-cdn-and-boundary-bypass.md` | 78–79, 81, 104–108 | Response header/body'de CDN/WAF izleri veya ağ-seviyeli bypass şüphesi varsa: request smuggling, DNS rebinding, CORS misconfiguration, referer/origin/host header bypass, WAF/CDN atlatma, WAF fail-open, static-file handler bypass |
| `references/protocol-architecture-advanced.md` | 69–73, 76–77, 82–90, 100, 103 | Sinyal alternatif protokol/mimari gösterdiğinde: GraphQL ileri teknikler, WebSocket/SSE, API version negotiation, feature flag, postMessage/localStorage/service worker, gRPC-Web, serverless, service mesh, webhook, presigned URL, pub-sub |
| `references/resource-catalog-edge-cases.md` | 51–53, 56–59, 91–99, 101–102 | Kaynak/akış bazlı özel durumlar: magic link/şifre sıfırlama, dosya upload, pagination, mobil/gizli endpoint, otomasyon araçları, genişletilmiş checklist, 200+ resource kategori referans listesi, admin impersonate, soft-delete |
| `references/agent-output-contract.md` | 109 | FAZ 9-10: Sonuç özeti, agent'ın her bulguda üretmesi gereken çıktı şablonu (STATUS/CLASS/ACTOR/OBJECT/EVIDENCE/CONFIDENCE vb.) ve skill'in güvenlik sınırı — her raporlama öncesi mutlaka okunmalı |

**Kural:** Bir bölüme çapraz referans (`bölüm N`) gördüğünde, N'in hangi
dosyada olduğunu yukarıdaki tablodan bul ve sadece o dosyayı oku — tüm
referans dosyalarını baştan okumaya gerek yoktur. Bölüm numaraları bu
ayrımdan bağımsızdır; her bölüm dosyalar arasında dağılmış olsa da kendi
orijinal numarasını (1–109) korur.

**Not — harf sonekli bölümler (`37a`, `67a`, `67b`):** Bu bölümler,
kendilerinden önceki bölümün (sırasıyla 37 ve 67) doğrudan devamı/eki
niteliğindedir ve bu numaralandırma yapısı bilinçli olarak korunmuştur —
ana numaralandırma notu yalnızca 43 ve 59'un kasıtlı olarak boş
bırakıldığını belirtir, harf soneklerinin ayrı bir istisna olduğunu ima
etmez. `37a` `evidence-methodology-severity.md` dosyasında bölüm 37 ile
birlikte, `67a`/`67b` ise `parser-normalization-and-bypass.md` dosyasında bölüm 67
ile birlikte yer alır — hiçbiri bölündüğü dosyadan ayrılmamıştır.

---
