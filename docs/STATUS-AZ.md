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
- Guard üçün müsbət, rədd, yanlış konfiqurasiya və abuse testləri.
- Private checkout, signature verification və Go yoxlamaları üçün CI.

Guard hələ bir SSH/RDP gateway-ə inteqrasiya olunmayıb. Bu, işlək remote-access
məhsulu və production təhlükəsizlik zəmanəti deyil.

## Hələ hazırlanmayıb

Login/MFA, vault və credential importu, hostname/IP təsdiqi üçün UI, SSH handshake,
terminal, RDP/guacd inteqrasiyası, clipboard, persistence, backup/restore,
Docker deployment və release automation.

## Növbəti mərhələ

Ayrıca laboratoriyada yalnız sintetik açar və hesablarla SSH/RDP texniki sınağı.
DNS-dən faktiki dial ünvanına qədər kitabxana sərhədi hazırdır; worker-ə
inteqrasiya hələ edilməyib. Növbəti iş versiyası pin edilmiş SSH dependency
review, host-key verification və sintetik remote PTY sınağıdır. Sonra terminal
input və RDP certificate/clipboard sınağı gəlir. Detallar `PROTOCOL-LAB.md`-dədir.
Real credential-lar login, authorization və vault mərhələsi yoxlanana qədər
istifadə edilmir. Tam brauzer və performance dəstəyi ölçüləndən sonra elan edilir.

## Brend

İstifadəçi Keybash adını seçib. Yaxın sahədə tanınmış eyniadlı məhsul ilkin
axtarışda tapılmayıb; adın hüquqi clearance-i tamamlanmayıb. Public buraxılışdan
əvvəl hədəf bazarlarda əmtəə nişanı və oxşar adlar yoxlanmalıdır. Repository-nin
yaradılması və public olması hüquqi uyğunluq təsdiqi deyil.
