# PPPP Camera Bridge – add-on Home Assistant

Stream **local, fără cloud** pentru camere ieftine pe protocol PPPP/iLnk
(A9, X5, camere bec E27, app „AX iot", „Little Stars" etc.), bazat pe
[aiopppp](https://pypi.org/project/aiopppp/) 0.2.3 + patch de stabilitate.

## Instalare
1. HA → Settings → Add-ons → Add-on Store → ⋮ → Repositories → adaugă URL-ul acestui repo.
2. Instalează **PPPP Camera Bridge**, setează opțiunile, Start.

## Opțiuni
| Opțiune | Implicit | Descriere |
|---|---|---|
| camera_ip | "" | IP fix al camerei (recomandat). Gol = broadcast (poate găsi mai multe camere). |
| username / password | admin / admin | Credențiale P2P ale camerei (alte valori întâlnite: 6666, 888888). |
| port | 4000 | Port HTTP pentru stream. |
| log_level | warning | debug/info/warning/error |

## Utilizare
- Interfață test: `http://<IP_HA>:4000/`
- Stream MJPEG: `http://<IP_HA>:4000/<DEVICE_ID>/v` (DEVICE_ID apare în log, ex. `FTZT-26976-MGLBY`)
- Comenzi: `POST /<DEVICE_ID>/c/<rotate|toggle-ir|toggle-lamp>`

### Home Assistant (camera MJPEG)
Settings → Devices & Services → Add Integration → **MJPEG IP Camera** → URL-ul de stream.

### Frigate
```yaml
cameras:
  bec_e27:
    ffmpeg:
      inputs:
        - path: http://<IP_HA>:4000/<DEVICE_ID>/v
          input_args: -f mjpeg
          roles: [detect, record]
```

## Recomandări
- Rezervă IP în router pentru cameră.
- După configurarea din app, blochează-i accesul la internet (merge 100% local).
- Închide app-ul vendorului cât rulează bridge-ul (o singură sesiune P2P simultan).

## Ce face patch-ul
aiopppp 0.2.3 crea o sesiune nouă la fiecare redescoperire; aceasta dădea timeout
și oprea tot serverul după ~30 s. Patch-ul ignoră camerele deja conectate,
refă sesiunile căzute fără restart și adaugă `--port`.
