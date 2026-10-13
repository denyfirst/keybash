# Keybash — cari vəziyyət

13 oktyabr 2026. İnkişaf private başladı. GitHub Free private branch protection
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
- Guard üçün müsbət, rədd, yanlış konfiqurasiya və abuse testləri.
- Private checkout, signature verification və Go yoxlamaları üçün CI.

Guard SSH kitabxanasının girişinə bağlanıb; RDP worker-ə inteqrasiya edilməyib.
Bu, işlək brauzer remote-access məhsulu və production təhlükəsizlik zəmanəti deyil.

## Hələ hazırlanmayıb

Login/MFA, vault və credential importu, hostname/IP/host-key təsdiqi üçün UI,
brauzer terminalı, real Linux shell sınağı, RDP/guacd inteqrasiyası, clipboard, persistence, backup/restore,
Docker deployment və release automation.

## Növbəti mərhələ

Ayrıca laboratoriyada yalnız sintetik açar və hesablarla SSH/RDP texniki sınağı.
SSH kitabxana sərhədi və dependency review hazırdır. Növbəti iş browser terminal
lab-ıdır: lokal xterm.js, məhdud transport, paste/keyboard və real Linux PTY
sınağı. Daha sonra RDP certificate/clipboard sınağı gəlir. Detallar
`PROTOCOL-LAB.md`-dədir. Kitabxana sınağı vim/tmux və browser rahatlığının sübutu deyil.
Real credential-lar login, authorization və vault mərhələsi yoxlanana qədər
istifadə edilmir. Tam brauzer və performance dəstəyi ölçüləndən sonra elan edilir.

## Brend

İstifadəçi Keybash adını seçib. Yaxın sahədə tanınmış eyniadlı məhsul ilkin
axtarışda tapılmayıb; adın hüquqi clearance-i tamamlanmayıb. Public buraxılışdan
əvvəl hədəf bazarlarda əmtəə nişanı və oxşar adlar yoxlanmalıdır. Repository-nin
yaradılması və public olması hüquqi uyğunluq təsdiqi deyil.
