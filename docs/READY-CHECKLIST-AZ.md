# Keybash — məhsulun hazır olması üçün qalan işlər

15 oktyabr 2026. Bu siyahı tarix vədi deyil; hər mərhələ faktiki sınaqla qəbul
edilir. Təhlükəsizlik bütün mərhələlərdə birinci prioritetdir. Yalnız self-host.

İndiki vəziyyət: ayrıca imzalanmış repository, hədəf/DNS/SSH kimlik nəzarəti,
brauzer SSH lab-ı və native RDP TLS/NLA/görüntü/izolyasiya lab-ı hazırdır.
Brauzer RDP görünüşü və mouse/klaviatura axını ayrıca lab-da yoxlanır;
Chromium-da faktiki native NLA peer-in input və görüntü dəyişiklikləri də ölçülür.
Hələ real credential saxlamaq və öz serverlərinə qoşulmaq üçün məhsul deyil.

1. **Brauzer bağlantı rahatlığı.** Native RDP görüntüsü və inputunun brauzerdə
   faktiki sınağı; sonra hər iki istiqamətdə məhdud Unicode mətn copy/paste,
   clipboard icazəsi/fallback, remote resize, keyboard layout, xüsusi düymələr,
   reconnect və logout. SSH-də vim/nano/tmux/htop və gündəlik işlər də yoxlanır.
2. **Login və MFA.** Lokal bootstrap, default passwordsuz hesab yaratma, MFA və
   recovery code, rate limit, CSRF/cookie və sessiya expiry/revocation.
   Daimi şifrələnmiş hesab, birdəfəlik bootstrap, offline blocklist, MFA/recovery
   və təkrar doğrulama ayrıca Linux lab-ında hazırdır (`CUSTODY-LAB.md`).
   Production quraşdırma, restore/rotation və quraşdırılan worker qalır.
3. **Credential vault və istifadəçi icazələri.** Şifrələnmiş persistence, ayrıca
   instance key, Ed25519 key/passphrase və password importu lab-da hazırdır.
   RDP domain sahəsi və digər key formatları qalır.
   Connection-credential əlaqəsi və sessiya icazələri artıq SSH/native RDP
   brauzer lab-ında birləşir (`OWNED-REMOTE-LAB.md`); quraşdırılan worker və
   operator target/trust konfiqurasiyası qalır. Reveal/export icazəsi və başqa hesabın
   connection/credential/socket-ına çıxışın rəddi. Real secret istifadə etməzdən
   əvvəl bu sərhədlər və bərpa modeli sınaqdan keçir.
4. **Gündəlik workspace.** Connection/credential ekranları, axtarış, qovluq,
   favorit, tablar, aydın xəta/bağlantı vəziyyəti, klaviatura ilə işləmə və
   Denyfirst dizaynı. Host-key/sertifikat təsdiqi və dəyişiklik zamanı bloklama UI-si.
   Operatorun sabit server siyahısı üçün host/port/IP/fingerprint baxışı,
   owner təsdiqi və dəyişmiş/legacy qərarların bloklanması artıq lab-da var
   (`SERVER-TRUST-LAB.md`). Operator konfiqurasiyasının quraşdırılması qalır.
   Root-a aid offline JSON catalog və SSH-only manager CLI inteqrasiyası
   artıq var (`OPERATOR-CATALOG-LAB.md`); quraşdırılan xidmət/RDP launcher qalır.
5. **Production worker və sessiya idarəsi.** Login/ownership ilə bağlı launcher,
   ayrıca credential ötürmə, minimal filesystem/syscall siyasəti, hədəfə məhdud
   çıxış, aggregate resurs/session limitləri, idle/absolute vaxt və aktiv ləğv.
   Ayrıca SSH prosesi və root olmayan gateway üçün authenticated manager
   lab-ı əlavə olunub (`SSH-MANAGER-LAB.md`). Quraşdırılan xidmət, ayrıca worker
   identity-si, aggregate cgroup və RDP manager inteqrasiyası qalır.
   Gateway və SSH manager üçün operatorun tənzimlədiyi paralel bağlantı
   hədləri və dolu tutum mesajı var (`SESSION-CAPACITY.md`). CPU/RAM/pids
   məhdudiyyətlərinin əməliyyat sistemində tətbiqi quraşdırma mərhələsinə aiddir.
   Linux systemd source plan və faktiki cgroup-v2 başlanğıc yoxlaması əlavədir
   (`LINUX-SERVICE-LAB.md`); ayrıca UID-lər, SSH worker, dayandırma/restart və
   CPU/pids/OOM kernel sınaqları CI-də tələb olunur. Avtomatik production
   quraşdırıcı, ölçülmüş server profilləri və RDP xidməti hələ qalır.
6. **Self-host paket.** Linux quraşdırma, müştərinin HTTPS-i, publish edilməyən
   DB/guacd portları, lokal/offline asset-lər, versiyalı migration/yeniləmə,
   dependency/license/SBOM və məhdud metadata audit.
7. **Backup və bərpa.** Şifrələnmiş export, ayrıca key recovery, təmiz instansiyaya
   restore və itmiş açarın nəticəsinin aydın izahı. Təkcə backup faylı yaratmaq
   kifayət etmir — onunla faktiki bərpa sınağı tələb olunur.
8. **Real istifadə və buraxılış yoxlamaları.** Windows/Linux serverləri,
   Chrome/Edge/Firefox/Safari və OS klaviatura/clipboard matrisi, yük/performance,
   pis bağlantı, upgrade/restore və hesablararası hücum sınaqları. Dəstək iddiaları
   yalnız yoxlanmış matrisi əhatə edir.
9. **Müstəqil təhlükəsizlik auditi və imzalanmış buraxılış.** Dəqiq namizəd commit
   üzrə audit, material tapıntıların həlli, qorunan signed tag, ayrıca build və
   təkrarlanan checksum, dependency/release manifesti və ayrıca təsdiqlənmiş
   buraxılış. CI və bizim self-review müstəqil audit hesab edilmir.

İlk işlək versiyaya PAM approval/rotation, komanda credential paylaşımı, SFTP,
audio/printer/disk redirection və mobil desktop bərabərliyi daxil deyil.
Porch və Rootwell yalnız oxunan referens olaraq qalır.
