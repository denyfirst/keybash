# Keybash — ayrıca test VM-də SSH/RDP yoxlaması

Bu yol yalnız disposable test mühiti və test hesabları üçündür. Hazır release,
production installer və ya audit olunmuş məhsul deyil. Sənin hazırda ayrıca VM-in
yoxdur; aşağıdakı hazırlıq VM-lər yaradıldıqdan sonra administrator tərəfindən
icra edilir. Porch və Rootwell-in yerləşdiyi hostda sınaq aparılmır.

## Lazım olan mühit

- Keybash üçün ayrıca **Ubuntu 24.04 x86-64, systemd və cgroup v2** VM.
- Hədəf olaraq ayrıca Linux SSH serveri və RDP/NLA aktiv Windows test serveri.
- Keybash VM-dən hədəflərə LAN/VPN yolu və sabit DNS adları/IP-lər.
- İlk sınaqda bir neçə GiB RAM olan VM ayır; aşağıdakı 1 GiB xidmət həddi hostun
  minimum RAM tövsiyəsi deyil. Ölçülmüş hardware profili hələ yoxdur.
- Tətbiq hələ `127.0.0.1:8443` üzərindədir. PC-dən ilk baxış üçün administrator
  SSH tunnel açır. Public HTTPS ingress və gündəlik tunnelsiz quraşdırma ayrıca
  mərhələdir; proxy ilə Host/Origin yoxlaması zəiflədilmir.

Hədəflərdə yalnız test məlumatı saxla. RDP clipboard testində fayl, şəkil,
printer, disk və audio ötürülməsi gözlənilmir. Windows-un konkret versiyası və
klaviatura matrisi hələ bu repoda VM ilə təsdiqlənməyib.

## Mənbəni hazırlamaq

Yeni VM-də adi administrator hesabı ilə repository-ni ayrıca klonla. İmzalanmış
PR merge commit-ini və `.github/commit-signers` etibar siyahısını ayrıca yoxla.
Build-i root olaraq işlətmə. Müvafiq əmrləri repository kökündə icra et:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends git golang-go python3 curl ca-certificates \
  build-essential clang cmake ninja-build pkg-config bubblewrap openssl \
  libssl-dev libcairo2-dev libjpeg-dev libpng-dev libwebp-dev libpango1.0-dev \
  libuuid1 uuid-dev
go version
go mod verify
mkdir -m 700 test-stage
mkdir -m 700 test-stage/bin
CGO_ENABLED=0 go build -trimpath -o test-stage/bin/ ./cmd/...
sh scripts/build-native-runtime.sh "$(pwd)/test-stage/native"
LD_LIBRARY_PATH="$(pwd)/test-stage/native/lib" python3 scripts/build-rdp-runtime.py \
  --prefix "$(pwd)/test-stage/native" --output "$(pwd)/test-stage/runtime"
```

Go `go.mod`-dakı dəqiq toolchain-ə keçməlidir. Build zamanı Go modulları və
pin edilmiş native source arxivləri yüklənir. Runtime üçün Node, CDN və cloud
xidməti lazım deyil. Build script mövcud output qovluğunun üstünə yazmır; uğursuz
build-dən sonra yeni staging adı seç. `--fixtures` yalnız CI üçündür.

## Hədəflərin kimliyi

`docs/OPERATOR-CATALOG-LAB.md`-dəki version 1 JSON catalog sxemindən istifadə et.
Hər server üçün təsadüfi 32 simvolluq lowercase hex ID, DNS adı, port, icazəli
IP-lər və public server kimliyi yazılır. Bunlar test nümunələridir; öz VM
şəbəkənə uyğunlaşdır:

```json
{
  "version": 1,
  "capacity": {"total": 2, "per_owner": 1},
  "protected_networks": ["10.90.0.0/24"],
  "targets": [
    {"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","name":"Linux test","protocol":"ssh",
     "hostname":"linux-test.example.test","port":22,"addresses":["10.91.0.10"],
     "ssh_host_key":"REPLACE_WITH_CANONICAL_ED25519_PUBLIC_HOST_KEY"},
    {"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","name":"Windows test","protocol":"rdp",
     "hostname":"windows-test.example.test","port":3389,"addresses":["10.91.0.20"],
     "rdp_certificate":"REPLACE_WITH_BASE64_DER_SERVER_CERTIFICATE"}
  ]
}
```

`protected_networks` Keybash VM-in, vault/control və digər qadağan olunmuş
servislərin yerləşdiyi şəbəkələri əhatə etməlidir. Keybash və hədəfləri ayrı test
subnet-lərində saxlamaq bu seçimi aydınlaşdırır. Bütün DNS cavabları qeyd edilən
IP-lərlə uyğun olmalıdır. IP və ya fingerprint dəyişərsə avtomatik qəbul yoxdur.

SSH host public key-ni Linux VM-in konsolundan `/etc/ssh/ssh_host_ed25519_key.pub`
faylından götür, comment-i çıxar və SHA256 fingerprint-i ayrıca yoxla. `ssh-keyscan`
nəticəsini təkbaşına etibar mənbəyi sayma. Test hesabı üçün ayrıca Ed25519 user
key yarat; production private key-ni bura gətirmə.

RDP üçün NLA açıq qalır. Sertifikat SHA-256 və ya daha güclü imza, ən azı RSA
2048/ECDSA P-256, DNS SAN, DigitalSignature key usage, serverAuth EKU və düzgün
tarix tələb edir. Adi avtomatik Windows sertifikatı bu profili ödəməyə bilər.
Sertifikatı test Windows-un konsolunda seç, RDP listener-ə bağla və public DER-ni
oradan export et; private key/PFX Keybash-a verilmir. Listener-in private key
oxuma icazəsini Microsoft-un təlimatına uyğun ver. Windows konfiqurasiyası üçün
[rəsmi listener sənədi](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remote-desktop-listener-certificate-configurations)
və [sertifikat yaratma parametrləri](https://learn.microsoft.com/en-us/powershell/module/pki/new-selfsignedcertificate?view=windowsserver2025-ps)
əsas götürülür. Bu Windows addımı hazırda faktiki VM acceptance nəticəsi deyil.

Windows test istifadəçisinə yalnız həmin VM-ə RDP hüququ ver. Firewall-da 3389
yalnız Keybash test VM-dən qəbul edilsin. Username ilkin olaraq ayrıca lokal
hesab adı ola bilər; ayrıca RDP domain sahəsi hələ əlavə edilməyib.

## Ayrı HTTPS test sertifikatı

Gateway HTTPS sertifikatı Windows RDP sertifikatından ayrıdır. Gateway leaf-in
SAN-ında **IP:127.0.0.1**, serverAuth və uyğun KU olsun; onu ayrıca test CA ilə
imzala. Private TLS key VM-də qalır. Yalnız public test CA-nı PC-nin test üçün
istifadə etdiyi trust store-a əlavə et və fingerprint-i ayrıca müqayisə et.
Brauzerdə certificate bypass/ignore seçimi işlətmə. Sınaq bitəndə bu əlavə test
etibarını çıxar. Test CA private key-ni gündəlik/production CA kimi istifadə etmə.

## Mənbə xidmətlərinin yerləşdirilməsi

Bu addımlar yalnız **təzə VM-də** administrator işidir. Aşağıdakı yollar artıq
mövcuddursa dayan; mövcud Keybash və ya başqa məhsulun üstünə yazma:

- `/usr/local/libexec/keybash`
- `/usr/local/lib/keybash/rdp`
- `/etc/keybash`
- `/var/lib/keybash`
- `keybash-gateway` və `keybash-worker` hesabları, seçəcəyin UID/GID-lər
- `keybash*.service`, `keybash.slice` və `/run/keybash*-manager`

Stage-dəki bütün `keybash*` Go binary-lərini root-a aid, group/world write olmayan
`/usr/local/libexec/keybash/` yoluna, minimal `runtime/` ağacını eyni qaydada
`/usr/local/lib/keybash/rdp/` yoluna köçür. Runtime-da symlink və hardlink qalmasın;
`cp -R` ilə yeni ağaca köçür, writable permissions vermə.

İki ayrı, başqa hesaba aid olmayan UID/GID seç. Nümunə yalnız **65533 və 65531
boşdursa** istifadə edilə bilər. Əvvəl `getent passwd 65533`, `getent group 65533`,
65531 və hesab adlarını yoxla. `0` və `65534` istifadə edilmir.

Binary və runtime yerləşdirildikdən sonra adi admin shell-də:

```sh
ssh_digest=$(sha256sum /usr/local/libexec/keybash/keybash-ssh-worker | cut -d ' ' -f 1)
rdp_digest=$(sha256sum /usr/local/libexec/keybash/keybash-rdp-worker | cut -d ' ' -f 1)
runtime_digest=$(/usr/local/libexec/keybash/keybash-rdp-inventory /usr/local/lib/keybash/rdp)
/usr/local/libexec/keybash/keybash-service-plan --gateway-uid=65533 --gateway-gid=65533 \
  --worker-uid=65531 --worker-gid=65531 --worker-digest="$ssh_digest" \
  --rdp-worker-digest="$rdp_digest" --rdp-runtime-digest="$runtime_digest" \
  --cpu-percent=200 --memory-mib=1024 --tasks=512 --output="$(pwd)/test-stage/units"
```

Plan yalnız yeni staging faylları yaradır. Yaranan beş faylı əvvəl nəzərdən keçir.
`keybash.conf` sysusers siyasətidir; onu `/etc/sysusers.d/keybash.conf` yoluna,
dörd unit-i `/etc/systemd/system/` yoluna root ownership/0644 ilə yerləşdir.
`systemd-sysusers /etc/sysusers.d/keybash.conf` ilə hesabları yarat.

`/var/lib/keybash`, `/etc/keybash/keys` və `/etc/keybash/tls` ayrıca gateway-ə aid
0700 qovluqlar olsun. Catalog `/etc/keybash/targets.json` root-a aid 0644 fayldır;
birbaşa `/etc/keybash` parent root-a aid 0755-dir. HTTPS cert/key gateway-ə aid
0600 fayllardır. Instance key catalog və TLS private key ilə eyni fayl deyil.

```sh
sudo /usr/local/libexec/keybash/keybash check-targets --config=/etc/keybash/targets.json
sudo -u keybash-gateway /usr/local/libexec/keybash/keybash init \
  --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key
sudo systemd-analyze verify /etc/systemd/system/keybash*.service /etc/systemd/system/keybash.slice
sudo systemctl daemon-reload
sudo systemctl start keybash-gateway.service
```

`init` birdəfəlik bootstrap secret göstərir. Yalnız lokal private terminalda
götür; log, screenshot, chat və shell argument-inə yazma. Default password yoxdur.
Xidmətlər cgroup controller/limit və ya identity uyğun gəlmədikdə başlamır.
Səbəbi aradan qaldır; limit yoxlamasını və namespace/seccomp-u söndürmə.

## PC-dən açmaq və yoxlamaq

PC-də VM-in SSH host kimliyini ayrıca təsdiqlədikdən sonra:

```sh
ssh -N -L 127.0.0.1:8443:127.0.0.1:8443 vm-admin@KEYBASH_TEST_VM_IP
```

PC-də 8443 boş olsun. Browser-dən etibarlı test HTTPS ilə
`https://127.0.0.1:8443` aç. Bootstrap → ayrıca login password → MFA/recovery
hazırlığı → test SSH key/password importu → connection → tam server fingerprint-i
ayrıca təsdiqlə → Connect ardıcıllığını keç. Status və stale trust xətası varsa
sertifikat/IP/saatı düzəlt; blanket trust vermə.

Bu tapşırıqları yoxla və gözlənilən/faktiki nəticəni qeyd et:

1. SSH-də Unicode, Ctrl+C, oxlar, vim/nano və PTY resize; çoxsətirli paste baxışı.
2. Windows-da Notepad aç, hər iki istiqamətdə Azərbaycan mətni, emoji və newline
   ötür. Remote copy-dən sonra Keybash-ın **Kopyala** düyməsini istifadə et.
   Lokal clipboard avtomatik dəyişməməlidir.
3. Clipboard icazəsini rədd et; mətn paneli ilə copy/paste işləməlidir. Paste
   ayrıca Enter əlavə etməməlidir. Fayl/HTML formatı channel kimi ötürülməməlidir.
4. 1280×720 və tam ekranı yoxla. Server display-update dəstəkləmirsə göstərilən
   remote ölçü təsdiqlənənədək dəyişmir; gizli reconnect/password retry yoxdur.
5. Logout, credential/connection silinməsi və manager stop aktiv sessiyanı kəssin.
   Yeni login əvvəlki sessiyanı avtomatik bərpa etməsin.
6. Yanlış password, dəyişmiş host key/sertifikat və başqa owner resursları rədd
   edilsin. Real credential-larla bunları sınama.

İlkin source test axınında 8 MiB lifetime output, native instruction/pixel-work,
32 KiB text, hər istiqamətdə 128 clipboard əməliyyatı, saniyədə 4 resize və
finite session/CPU/RAM/pids hədləri var. Bunlar test containment üçündür;
uzun gündəlik sessiya və geniş brauzer/Windows matrisi hələ qəbul edilməyib.
Resurs tükənməsi aktiv sessiyanı da bağlaya bilər; limitsiz rejim yoxdur.

Sınaqdan sonra `systemctl stop keybash-gateway keybash-ssh-manager keybash-rdp-manager`
ilə xidmətləri dayandır və disposable VM-ləri snapshot siyasətinə uyğun saxla
və ya sil. Production-a keçməzdən əvvəl restore/upgrade, sizing, public ingress
və müstəqil dəqiq-candidate audit mərhələləri ayrıca tamamlanmalıdır.
