# Keybash — lokal interaktiv UI demo

15 oktyabr 2026. Məqsəd interfeysi özün yoxlayıb çatışmazlıqları bildirməkdir.
Bu, quraşdırılan məhsul və real server bağlantısı deyil. Porch və Rootwell-ə
toxunmur. Yalnız Keybash repository-sindəki development alətlərindən istifadə edir.

## Açmaq

Windows PowerShell-də:

```powershell
Set-Location C:\Users\Rash\projects\keybash
./scripts/demo.ps1
```

Go-nun `go.mod`-da göstərilən versiyası, Node və `web/` üçün lockfile ilə
qurulmuş development asılılıqları lazımdır. Hazırkı iş kompüterində bunlar var.
Skript Windows-da quraşdırılmış Edge-i ayrıca, müvəqqəti brauzer kontekstində
açır. Normal Edge profilinə, əməliyyat sisteminin TLS etibarına və başqa
layihələrin konfiqurasiyasına dəyişiklik etmir. Əlavə browser quraşdırmır.
Başqa development sistemində əvvəlcə `web/` üçün pinned pnpm/frozen-lockfile
asılılıqlarını və Playwright Chromium-u mühəndislik qaydasına uyğun qurmaq lazımdır.

Demo bir bələdçi və iş yeri səhifəsi açır. Bələdçidə **İş yerini aç** düyməsi,
demo istifadəçisi/şifrəsi, hazırkı MFA kodu və qalan birdəfəlik bərpa kodları var.
Hər açılışda yeni müvəqqəti instance və test açarları yaradılır. Giriş və MFA
ilk dəfə adi UI ilə avtomatik tamamlanır; həssas əməliyyatlar üçün iki dəqiqəlik
icazə adi server yoxlamalarından alınır. MFA/CSRF/ownership bypass yoxdur.

MFA kodunu təkrar işlətmək olmaz. Açılışda işlənən kod bitənədək növbəti kodu
gözlə və ya bələdçidəki istifadə olunmamış bərpa kodlarından birini işlət.
Sonrakı əlavə/silmə və yeni bağlantı açılışı üçün lazım gəlsə hesab səhifəsində
demo giriş şifrəsi və yeni MFA/bərpa kodu ilə təkrar doğrula. Şifrəni/MFA-nı
dəyişsən, bələdçidəki ilkin məlumatlar artıq uyğun olmaya bilər; demo yenidən
başladılaraq təmiz vəziyyətə qayıdır.

## Nəyi yoxlamaq olar

- **Hesab:** login, MFA, logout, təkrar doğrulama, şifrəli qeyd siyahısı və
  synthetic qeydlər əlavə etmək/göstərmək/silmək.
- **Bağlantılar:** iki hazır nümunədən **Qoşul**, yeni connection yaratmaq,
  seçicilər, adlandırma, pəncərələr arasında gəzmək.
- **Terminal:** `help`, `whoami`, `hostname`, `pwd`, `ls`, `uname`, `date`,
  `echo Salam dostum`, `clear`, `exit`; Unicode yazı, seçim/copy, paste preview,
  Ctrl+C, Ctrl+L və ölçü dəyişəndə terminal görünüşü.
- **Desktop:** öz üzərində SIMULATION yazılmış test görüntüsü; klik və yazı
  görüntünü dəyişir. Backspace, Enter, lokal fullscreen və Bağla düyməsi.
- **Ləğv:** iki bağlantını açıb ayrıca hesab səhifəsində **Hesabdan çıx** seç;
  hər iki görünüş bağlanmalı və görüntü təmizlənməlidir.

Terminal sintetik əmr siyahısıdır, Linux shell deyil. `vim`, `tmux`, real fayl
sistemi, process/job control, shell quoting və həqiqi SSH protokolu burada yoxdur.
Desktop Windows deyil və bu preview native RDP/NLA serveri işə salmır. Əvvəlki
ayrıca SSH və native RDP CI testləri protokol sübutudur; bu demo onları əvəz etmir.
RDP clipboard və remote resize hələ bağlıdır. Demo metadata/səhifə başlıqlarında
simulyasiya olduğu görünür; heç bir real serverə və lokal shell-ə keçid yoxdur.

**Yalnız uydurma test məlumatı daxil et.** Demo real credential qəbul etmək üçün
hazırlanmayıb. Test browser kontekstində HTTP sorğuları həmin təsadüfi loopback
HTTPS origin-ə süzülür; bu ümumi host/browser egress sandbox iddiası deyil.
Fixture sertifikatının qəbul edilməsi yalnız ayrıca test browser
kontekstindədir. Production target guard, pin və Linux storage admission
qaydalarına demo istisnası əlavə olunmayıb. Portable storage/worker seam-ləri
yalnız `browserlab` test fayllərindədir və məhsul binary-sinə daxil deyil.

Bütün demo brauzer pəncərələrini bağlamaq və ya skriptdə Ctrl+C dayandırır.
Bir saatlıq maksimum vaxt da var. Normal çıxışda test DB-si müvəqqəti qovluqdan
silinir; məcburi process/kompüter dayananda OS temp-də yalnız synthetic encrypted
test qalıqları qala bilər. Instance encryption key və synthetic private key
yalnız process yaddaşında olur; demo restart-dan sonra davam etmir. Browser
profilinin zəmanətli forensic silinməsi iddia edilmir.
Mövcud iki aktiv/pending bağlantı və hər axında 8 MiB output kimi lab limitləri
qüvvədədir. Limitə çatanda bağlantı bağlana bilər; ayrıca yeni sessiya aç.

## Avtomatik yoxlama və rəy

```powershell
./scripts/demo.ps1 -Check
```

Headless Edge yoxlaması bələdçini, adi bootstrap/MFA/reauth axınını, iki owned
nümunəni, terminal cavabını, desktop-da klaviatura/siçanın faktiki pixel
dəyişikliyini və logout ləğvini yoxlayır. Linux CI eyni sınağı Chromium/race ilə
yerinə yetirir. Test-only parser malformed/clipboard/out-of-bounds inputu rədd
edir. Mövcud transport/identity və native təhlükəsizlik gate-ləri saxlanılır.

Rəy üçün hansı ekran, hansı addım və nə gözlədiyini yaz. Məsələn:
“Desktop → tam ekran → Esc: ölçü belə qaldı; belə olmasını istəyirdim”.
Credential və recovery code-ları rəy mətninə və screenshot-a daxil etmə.
