# Keybash — cari vəziyyət

19 oktyabr — operator server konfiqurasiyası: root-a aid, dəyişdirilməsi
məhdud JSON faylından host/port/IP və public SSH/RDP kimliyi yoxlanır.
`check-targets` şəbəkəyə və bazaya çıxmadan yoxlayır. Ayrıca `serve-ssh-lab`
əmri root olmayan Linux/amd64 gateway-də SSH-only siyahını mövcud manager,
login/MFA və owner təsdiqinə bağlayır. `serve-lab` custody-only qalır.
Bu quraşdırıcı və production buraxılışı deyil: `OPERATOR-CATALOG-LAB.md`.

19 oktyabr — server kimliyi interfeysi: operatorun sabit server siyahısında
host/port/IP-lər və SSH/RDP fingerprint-i görünür. Yeni bağlantı və yenidən
təsdiq üçün tam fingerprint, təzə şifrə/MFA və cari target snapshot-u tələb
olunur. Kimlik/port/IP siyahısı dəyişəndə və köhnə qeyddə təsdiq olmayanda
qoşulma bağlı qalır. Operator konfiqurasiyası və production quraşdırması
ayrıca mərhələdir: `SERVER-TRUST-LAB.md`.

19 oktyabr əlavəsi: root olmayan gateway üçün ayrıca SSH manager sərhədi
qurulub. Unix socket-də konkret UID/GID yoxlanır; manager yalnız sabit,
hash-lə təsdiqli worker-i başladır. Sessiyanın açarı və terminal axını
gateway-dən birbaşa worker-ə gedir. Ayrı istifadəçi ilə SSH, yanlış peer,
descriptor/replay/limit və shutdown sınaqları CI gate-inə əlavə olunub.
Bu hələ quraşdırılan production xidməti deyil: `SSH-MANAGER-LAB.md`.

16 oktyabr əlavəsi: SSH protokolunu ayrıca Linux/amd64 prosesində işlədən
manager/worker sərhədi əlavə olunub. Şəxsi namespace-lər, məhdud syscall siyasəti,
bir sessiyanın açarı və yalnız əvvəlcədən icazəli TCP descriptor-u istifadə edir.
Bu privileged laboratoriya manager-idir; public root gateway və quraşdırılan
service deyil. Məhdudiyyətlər və yoxlama: `SSH-PROCESS-LAB.md`.

15 oktyabr 2026. İnkişaf private başladı. GitHub Free private branch protection
vermədiyi üçün istifadəçi public repository-yə keçidi təsdiqlədi.

## Hazır olan təməl

- Porch və Rootwell-dən ayrı repository və iş qovluğu.
- Eyni Denyfirst public commit/tag və release signing identity-ləri.
- Məhsul planı, mühəndislik qaydaları və roadmap.
- IP/port səviyyəsində qeydiyyatdan keçmiş hədəflərə bağlı outbound guard.
- Hostname/port üçün ayrıca təsdiqlənmiş IP-lər; bir DNS nəticəsinin yoxlanıb
  həmin literal IP ilə bağlantıya ötürülməsi. DNS yeni IP-ni təsdiqləyə bilmir.
- DNS rebinding, qarışıq cavab, timeout, IPv6 və hostname fuzz sınaqları.
- Ed25519 host açarı təsdiqindən sonra SSH key authentication; remote PTY/shell
  sorğuları, Unicode axını, resize və aktiv bağlantının ləğvi üçün kitabxana.
- Sintetik SSH serveri və host-key/authentication/forwarding mənfi sınaqları.
- Lokal xterm ilə brauzer terminal lab-ı, məhdud WSS axını və paste preview.
- TLS 1.3/loopback/Origin/owner sərhədi, tək socket, logout və expiry ləğvi.
- Edge-də sintetik SSH; Linux CI-də Chromium və real Bash PTY sınağı.
- Credential qəbul etməyən RDP başlanğıc/TLS lab-ı: SHA-256 sertifikat pini,
  zəif rejim/TLS və yanlış sertifikatların rəddi.
- Unicode mətn clipboard protokolunun 32 KiB limitli, ayrıca sessiya/buffer sınağı.
- Linux CI-də boş şəbəkə namespace-i, səlahiyyətlərin endirilməsi və egress rəddi;
  bu ilkin sınaq bütün bağlantıları rədd edir.
- Pinned Guacamole/FreeRDP ilə ayrıca native Linux lab-ı: worker-in öz TLS
  sertifikat yoxlaması, NLA hesab doğrulaması və məhdud PNG masaüstü axını.
- Birdəfəlik bağlantı broker-i, ayrıca filesystem/network/PID mühiti,
  səlahiyyətlərin endirilməsi, yanlış IPC istifadəçisinin rəddi və sessiya ləğvi.
- Native sertifikat yoxlamasını hər iki istiqamətdə qəsdən pozan sınaqlar;
  original kod bərpa edilir və bütün native sınaqlar təkrar keçir.
- Brauzer RDP lab-ı: yoxlanmış PNG görüntüsü, klaviatura/siçan, fokus itəndə
  basılı düymələrin buraxılması, lokal fullscreen və logout zamanı görüntünün silinməsi.
- Linux-da faktiki NLA worker-dən Chromium-a görüntü və input sınaqları;
  native clipboard və dinamik ekran kanalları hələ bağlıdır.
- Guard üçün müsbət, rədd, yanlış konfiqurasiya və abuse testləri.
- Private checkout, signature verification və Go yoxlamaları üçün CI.
- Ayrıca şifrə ilə giriş lab-ı: fərdi hesablar, Argon2id, giriş cəhd limitləri,
  qorunan cookie/CSRF, şifrə dəyişmə, idle/absolute expiry və sessiya ləğvi.
- Denyfirst üslubunda giriş/hesab ekranı və ayrıca Linux custody lab-ı.
- Daimi şifrələnmiş hesablar, birdəfəlik bootstrap, məcburi MFA/bərpa kodları,
  restart-dan sonra replay rəddi və ayrıca instance key.
- Öz hesabına aid Ed25519 açar/passphrase və şifrə saxlama/göstərmə/silmə;
  həssas əməliyyatlar üçün şifrə + təzə MFA ilə təkrar doğrulama.

Guard SSH kitabxanasına və native RDP broker kitabxanasının girişinə bağlıdır.
Native sınaqlarda yalnız test fayllarına aid sintetik loopback bağlantısı var.
Bu, işlək brauzer remote-access məhsulu və production təhlükəsizlik zəmanəti deyil.

Login/vault və connection icazələri artıq SSH/native RDP brauzer lab-ına
bağlanıb: birdəfəlik icazə, server kimliyi versiyası və logout ləğvi yoxlanır.

Özün UI-ni yoxlamaq üçün `./scripts/demo.ps1` lokal interaktiv preview açır.
Login/MFA, iki owned connection, simulyasiya terminalı və test desktop-u var.
Bu preview real Linux/Windows deyil; real credential işlətmir. Açmaq və
məhdudiyyətlər: `INTERACTIVE-DEMO-AZ.md`.

## Hələ hazırlanmayıb

Hələ quraşdırılan worker/xidmətlər və operator konfiqurasiyasının deployment-i,
məhsul workspace-i, real şəbəkə hostları və tam browser/clipboard matrisi,
hazır RDP workspace/copy-paste, backup/restore/key rotation,
Docker deployment və release automation.

## Növbəti mərhələ

Ayrıca laboratoriyada yalnız sintetik açar və hesablarla SSH/RDP texniki sınağı.
SSH/brauzer lab sərhədi və dependency review hazırdır. RDP ilkin negotiation/TLS
və mətn protokol lab-ına native TLS/NLA, masaüstü görüntüsü və izolyasiya olunmuş
worker/broker və brauzer görüntü/input sınaqları əlavə olunub. Növbəti protokol işi
resize, keyboard layout, reconnect və ayrıca sessiyaya bağlı məhdud mətn
copy/paste-in faktiki sınağıdır. Daimi hesab, bootstrap/MFA və vault lab-ı
`CUSTODY-LAB.md`-dədir. Vahid authorization/revocation axını
`OWNED-REMOTE-LAB.md`-də yoxlanır. Quraşdırılan worker və operator target/trust
konfiqurasiyası növbəti inteqrasiya mərhələsidir. Protokol detalları
`PROTOCOL-LAB.md`-dədir. Vim/tmux və tam browser/OS rahatlığı hələ sübut edilməyib.
Lab məhsul login/vault sisteminin və install edilən servisin yerini tutmur.
Real credential-lar login, authorization və vault mərhələsi yoxlanana qədər
istifadə edilmir. Tam brauzer və performance dəstəyi ölçüləndən sonra elan edilir.

## Brend

İstifadəçi Keybash adını seçib. Yaxın sahədə tanınmış eyniadlı məhsul ilkin
axtarışda tapılmayıb; adın hüquqi clearance-i tamamlanmayıb. Public buraxılışdan
əvvəl hədəf bazarlarda əmtəə nişanı və oxşar adlar yoxlanmalıdır. Repository-nin
yaradılması və public olması hüquqi uyğunluq təsdiqi deyil.
