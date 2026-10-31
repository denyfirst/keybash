# Keybash — quraşdırıcı ilə test serverinə quraşdırma

Bu bələdçi **təzə** Ubuntu 24.04 x86-64 VM üçündür (systemd və cgroup v2 ilə).
Quraşdırıcı mövcud heç bir faylın, xidmətin və ya hesabın üstünə yazmır; hər şeyi
əvvəlcə yoxlayır, bir problem olsa heç nəyə toxunmadan dayanır. Texniki
təfərrüat: `INSTALL.md`. Bu hələ rəsmi buraxılış deyil: serverdə yalnız test
məlumatı saxla.

## 1. Mənbəni yığmaq (adi istifadəçi ilə, root yox)

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends git golang-go python3 curl ca-certificates \
  bubblewrap openssl openssh-client
git clone https://github.com/denyfirst/keybash.git
cd keybash
sh scripts/build-stage.sh "$HOME/keybash-stage"
```

Windows serverlərinə də (RDP) qoşulmaq istəyirsənsə, əlavə paketləri qur və
`--with-rdp` əlavə et (bu, 15–30 dəqiqə çəkə bilər):

```sh
sudo apt-get install --no-install-recommends build-essential clang cmake ninja-build pkg-config \
  libssl-dev libcairo2-dev libjpeg-dev libpng-dev libwebp-dev libpango1.0-dev libuuid1 uuid-dev
sh scripts/build-stage.sh "$HOME/keybash-stage" --with-rdp
```

## 2. HTTPS sertifikatı (test üçün)

Brauzerin istifadə edəcəyi ad və ya ünvan üçün:

```sh
"$HOME/keybash-stage/bin/keybash-test-tls" --name keybash.lan --output "$HOME/keybash-tls"
```

(Tunnel ilə `127.0.0.1` istifadə edəcəksənsə: `--address 127.0.0.1`.)

Əmr `ca.pem`, `cert.pem`, `key.pem` yaradır və CA-nın barmaq izini çap edir.
Bu CA **yalnız bu bir ada** imza ata bilər və gizli açarı heç vaxt diskə yazılmayıb.
`ca.pem`-i PC-yə köçür, barmaq izini müqayisə et və Windows-da
"Etibarlı kök sertifikat orqanları"na əlavə et. Belə olanda brauzer xəbərdarlıq
göstərməyəcək.

## 3. Serverlərin siyahısı

`targets.json` faylında qoşulacağın serverləri yaz (format:
`OPERATOR-CATALOG-LAB.md`). Hər SSH serverinin host açarını və hər Windows
serverinin RDP sertifikatını ayrıca, etibarlı yolla götür.

## 4. Quraşdırma (root ilə)

Yalnız bu maşında (tunnel ilə) istifadə üçün:

```sh
sudo sh scripts/install.sh --stage="$HOME/keybash-stage" --catalog="$HOME/targets.json" \
  --tls-cert="$HOME/keybash-tls/cert.pem" --tls-key="$HOME/keybash-tls/key.pem"
```

Ofisdə hamı tunnelsiz qoşulsun deyə (yalnız yazdığın şəbəkələrə açıqdır,
ətraflı `LAN-INGRESS.md`):

```sh
sudo sh scripts/install.sh --stage="$HOME/keybash-stage" --catalog="$HOME/targets.json" \
  --tls-cert="$HOME/keybash-tls/cert.pem" --tls-key="$HOME/keybash-tls/key.pem" \
  --listen=192.168.1.10:8443 --allow-from=192.168.1.0/24 --server-name=keybash.lan
```

Sonda terminal **bir dəfə** iki kod göstərir:

- **Bootstrap kodu** — ilk hesabı yaratmaq üçün, 15 dəqiqə etibarlıdır.
- **Instance açarının bərpa kodu** (`KB1-…`) — kağıza və ya parol menecerinə
  yaz, serverdən və backup-lardan **ayrı** saxla. Onsuz heç bir backup bərpa
  olunmur.

Bu kodları chat-a, ekran şəklinə və ya qeydlərə yazma.

## 5. İlk giriş

Brauzerdə çap olunan ünvanı aç (məsələn `https://keybash.lan:8443/login`).
Bootstrap kodu ilə ilk hesabı yarat, sonra MFA və bərpa kodlarını qur.

Bootstrap kodunun vaxtı bitibsə:

```sh
sudo systemctl stop keybash-gateway
sudo setpriv --reuid=keybash-gateway --regid=keybash-gateway --clear-groups --reset-env -- \
  /usr/local/libexec/keybash/keybash bootstrap-renew --data=/var/lib/keybash --key-file=/etc/keybash/keys/instance.key
sudo systemctl start keybash-gateway
```

## Sonradan server əlavə etmək

Siyahıya JSON yazmadan və açarı əl ilə köçürmədən server əlavə etmək üçün:

```sh
sudo /usr/local/libexec/keybash/keybash server-add --config=/etc/keybash/targets.json \
  --name="Veb server" --host=192.168.1.20 --port=22
```

Keybash serverin kimliyini (Ed25519 host key) özü oxuyur, barmaq izini göstərir
və heç nəyi dəyişmədən soruşur. Həmin serverin öz konsolunda
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` ilə müqayisə et və eynidirsə
`yes` yaz. Sonra siyahını oxuması üçün Keybash-i yenidən başlat. Bu zaman açıq
sessiyalar bağlanır:

```sh
sudo systemctl restart keybash-ssh-manager keybash-gateway
```

Qorunan şəbəkələrdəki, loopback və ya link-local ünvanlar, eyni ünvan və port
ikinci dəfə əlavə olunmur. Belə ünvanlara qoşulmağa heç cəhd edilmir. Siyahı
yalnız oxunduğu andan bəri dəyişməyibsə və yeni siyahı Keybash-in özü kimi
yüklənə bilirsə əvəz olunur.

## Yeniləmək

Serverdəki Keybash qovluğunda əvvəl adi istifadəçi ilə yeni versiyanı yığ,
sonra root ilə qur:

```sh
git pull --ff-only
sh scripts/build-stage.sh ~/keybash-stage-$(git rev-parse --short HEAD)    # RDP varsa: --with-rdp
sudo sh scripts/upgrade.sh --stage=$HOME/keybash-stage-$(git rev-parse --short HEAD)
```

`upgrade.sh` yalnız proqramları dəyişir. Hesablar, ayarlar, serverlərin
siyahısı, sertifikat, açarlar və məlumatlar yerində qalır. Heç nəyi dəyişməzdən
əvvəl hər şeyi yoxlayır. Köhnə versiyanın surətini `/var/backups/keybash`
qovluğuna qoyur. Yeni versiya başlamasa, köhnəsini özü geri qaytarıb başladır.
Yeniləmə zamanı açıq sessiyalar bağlanır. Workspace-dəki **Installation**
səhifəsi eyni əmrləri və işləyən versiyanı göstərir.

## Silmək

```sh
sudo sh scripts/uninstall.sh
```

Proqramlar və xidmətlər silinir; baza (`/var/lib/keybash`), açar və
sertifikatlar (`/etc/keybash`) və iki hesab saxlanılır. Tam təmiz yenidən
quraşdırma üçün (əvvəl lazım olsa backup al):

```sh
sudo rm -rf /var/lib/keybash /etc/keybash
sudo userdel keybash-gateway; sudo userdel keybash-worker
sudo groupdel keybash-gateway; sudo groupdel keybash-worker
```

## Quraşdırıcı nəyi rədd edir

- root olmadan işə salmaq;
- maşında Keybash-dən qalan istənilən fayl, xidmət və ya hesab;
- yanlış və ya RDP olmadan RDP serverli kataloq;
- brauzerin istifadə edəcəyi adı əhatə etməyən və ya müddəti bitmiş sertifikat;
- `--allow-from` olmadan LAN ünvanı, `0.0.0.0` və bütün internet;
- düzgün olmayan limit və ya ID.

Bu halların hamısında quraşdırıcı heç nəyə toxunmadan dayanır.
