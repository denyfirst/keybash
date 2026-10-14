# Keybash — cari vəziyyət

14 oktyabr 2026. İnkişaf private başladı. GitHub Free private branch protection
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
- Native clipboard və dinamik ekran kanalları bağlıdır; brauzer RDP
  workspace-i və hazır RDP copy/paste hələ hazırlanmayıb.
- Guard üçün müsbət, rədd, yanlış konfiqurasiya və abuse testləri.
- Private checkout, signature verification və Go yoxlamaları üçün CI.

Guard SSH kitabxanasına və native RDP broker kitabxanasının girişinə bağlıdır.
Native sınaqlarda yalnız test fayllarına aid sintetik loopback bağlantısı var.
Bu, işlək brauzer remote-access məhsulu və production təhlükəsizlik zəmanəti deyil.

## Hələ hazırlanmayıb

Login/MFA, vault və credential importu, hostname/IP/host-key təsdiqi üçün UI,
məhsul workspace-i, real şəbəkə hostları və tam browser/clipboard matrisi,
brauzer RDP inteqrasiyası, persistence, backup/restore,
Docker deployment və release automation.

## Növbəti mərhələ

Ayrıca laboratoriyada yalnız sintetik açar və hesablarla SSH/RDP texniki sınağı.
SSH/brauzer lab sərhədi və dependency review hazırdır. RDP ilkin negotiation/TLS
və mətn protokol lab-ına native TLS/NLA, masaüstü görüntüsü və izolyasiya olunmuş
worker/broker sınaqları əlavə olunub. Növbəti iş brauzer RDP görüntüsü, klaviatura,
resize və ayrıca sessiyaya bağlı məhdud mətn copy/paste-in faktiki sınağıdır. Detallar
`PROTOCOL-LAB.md`-dədir. Vim/tmux və tam browser/OS rahatlığı hələ sübut edilməyib.
Lab məhsul login/vault sisteminin və install edilən servisin yerini tutmur.
Real credential-lar login, authorization və vault mərhələsi yoxlanana qədər
istifadə edilmir. Tam brauzer və performance dəstəyi ölçüləndən sonra elan edilir.

## Brend

İstifadəçi Keybash adını seçib. Yaxın sahədə tanınmış eyniadlı məhsul ilkin
axtarışda tapılmayıb; adın hüquqi clearance-i tamamlanmayıb. Public buraxılışdan
əvvəl hədəf bazarlarda əmtəə nişanı və oxşar adlar yoxlanmalıdır. Repository-nin
yaradılması və public olması hüquqi uyğunluq təsdiqi deyil.
