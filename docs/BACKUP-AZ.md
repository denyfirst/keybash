# Keybash — ehtiyat nüsxə, açarın bərpası və restore

Keybash-də saxlanmış açar və şifrələri yalnız **iki şey birlikdə** aça bilər:
məlumat qovluğundakı baza (`custody.db`) və ayrıca qovluqdakı 32 baytlıq
**instance açarı**. Ehtiyat nüsxə (backup) bazanı köçürür; açarın özü isə bir
dəfə, ayrıca yazılıb saxlanılır. Texniki təfərrüat: `BACKUP-RESTORE.md`.

Bu əmrlər oflayn operator əmrləridir: `backup` və `key-export` işləyərkən
xidmət dayandırılmalıdır (baza eyni anda yalnız bir proses tərəfindən açılır).

## 1. Quraşdırmadan dərhal sonra: açarın bərpa kodu

```sh
keybash key-export --data /srv/keybash/data --key-file /srv/keybash/keys/instance.key
```

Çıxış `KB1-` ilə başlayan 73 simvolluq bir koddur. Onu **serverdən və
backup-lardan ayrı** saxla: kağızda (seyfdə) və ya parol menecerində.

- Bu kod itərsə və server də sıradan çıxarsa, heç bir backup açılmayacaq —
  nə Keybash, nə başqası bərpa edə bilməz.
- Kim həm backup-ı, həm də bu kodu ələ keçirsə, bütün saxlanmış məlumatı
  oxuya bilər. Ona görə ikisini heç vaxt bir yerdə saxlama.

## 2. Müntəzəm backup

```sh
sudo systemctl stop keybash
keybash backup --data /srv/keybash/data --key-file /srv/keybash/keys/instance.key \
  --out /mnt/offsite/keybash-2026-10-27.backup
sudo systemctl start keybash
```

- Fayl yalnız yeni yaradılır (0600); mövcud faylın üstünə yazılmır.
- Açarın qovluğuna backup yazmaq rədd edilir: açarın yanında saxlanan backup
  heç nəyi qorumur.
- Faylda nə açar, nə də açıq şəkildə şifrə/açar mətni var; istifadəçi adları
  belə görünmür. Onu başqa diskə və ya başqa yerə köçürmək təhlükəsizdir.
- Canlı `custody.db` faylını kopyalamaq backup deyil — yalnız bu əmrdən istifadə et.

## 3. Bərpa (təmiz serverdə)

1. Keybash-i quraşdır və iki boş şəxsi qovluq yarat (`init` işlətmə):
   ```sh
   mkdir -m 700 /srv/keybash/data /srv/keybash/keys
   ```
2. Açarı bərpa kodundan yaz (kod klaviaturadan və ya fayldan oxunur, heç vaxt
   əmr sətrində verilmir):
   ```sh
   keybash key-import --data /srv/keybash/data --key-file /srv/keybash/keys/instance.key
   ```
   Kodda bir simvol səhv yazılsa, əmr rədd edir və heç nə yazmır.
3. Backup-ı bərpa et:
   ```sh
   keybash restore --data /srv/keybash/data --key-file /srv/keybash/keys/instance.key \
     --in /mnt/offsite/keybash-2026-10-27.backup
   ```
4. Çıxışda hər hesab üçün bir **birdəfəlik setup kodu** olur. Hər istifadəçiyə
   öz kodunu ayrıca ver.

### Niyə hər kəs MFA-nı yenidən qurur

Köhnə backup, ondan sonra istifadə edilmiş bərpa kodlarını və ya sızdığı üçün
dəyişdirilmiş MFA-nı geri gətirə bilərdi. Ona görə restore hər hesabın MFA-sını
və bərpa kodlarını silir. İstifadəçi öz şifrəsi və setup kodu ilə daxil olur,
authenticator tətbiqindəki köhnə Keybash qeydini silib yenisini əlavə edir.
Şifrələr dəyişmir.

## Bilməli olduqların

- **Səhv açar** və ya başqa serverin açarı ilə restore alınmır və heç bir fayl
  yaratmır. Dəyişdirilmiş və ya zədələnmiş backup da rədd edilir.
- Restore yalnız **boş** məlumat qovluğuna yazır; mövcud bazanın üstünə yazmır.
- Backup bir an üçündür: ondan sonra silinən və ya dəyişdirilən açar/şifrələr,
  dəyişdirilmiş hesab şifrələri köhnə halına qayıdır. Bilərəkdən dəyişdirdiyin
  sirri yenidən dəyiş; şifrəsi sonradan dəyişən istifadəçi üçün
  `account-recover` istifadə et.
- Bərpa olunmuş serveri köhnəsi ilə eyni vaxtda eyni açarla işlətmə.
- **Bərpanı yoxla:** vaxtaşırı backup-ı ayrıca boş qovluğa restore edib
  açıldığını yoxla, sonra həmin qovluğu sil. Yalnız backup yaratmaq kifayət deyil.

Hələ olmayanlar: xidməti dayandırmadan və ya avtomatik (cədvəllə) backup,
backup faylına ayrıca parol, köhnə backup-ların silinməsi, açarın dəyişdirilməsi
(rotation).
