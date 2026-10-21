# PHP2Shell Web Check

[![CI & Pages](https://github.com/kaiste99/php2shell-web-check/actions/workflows/ci-pages.yml/badge.svg)](https://github.com/kaiste99/php2shell-web-check/actions/workflows/ci-pages.yml)

Passiver Check, ob ein Webserver von **PHP2Shell** betroffen sein könnte (CVE-2026-109618, CVE-2026-109619): Remote Code Execution in PHP ohne Login, CVSS v4 9.2.
Behoben in **PHP 8.5.12, 8.4.27, 8.3.36 und 8.2.35**. Das Frontend nutzt OpenUI5 (Horizon), das Backend ist Node.js ohne Laufzeit-Dependencies. Ein Projekt von [BALTX.COM](https://www.baltx.com).

> **Wichtig:** Eine Prüfung von aussen liefert ein Indiz, keinen Beweis. Backports der Distributionen, Mitigations und weitere Server hinter einem Load-Balancer sind von aussen nicht sichtbar. Verbindlich ist nur die [Prüfung auf dem Server](#prüfung-auf-dem-server).

## Nutzung

| Weg | Was du brauchst | Was geprüft wird |
| --- | --- | --- |
| **GitHub Pages**: [kaiste99.github.io/php2shell-web-check](https://kaiste99.github.io/php2shell-web-check/) | einen Browser | eingefügte Response-Header, z.B. aus `curl -sIL https://www.example.ch`. Die Auswertung läuft komplett im Browser. |
| **GitHub Actions**: [PHP2Shell Check](https://github.com/kaiste99/php2shell-web-check/actions/workflows/check.yml) → «Run workflow» | Schreibrechte im Repo | eine URL; das Ergebnis steht in der Zusammenfassung des Laufs |
| **Lokal**: `npm install && npm start` → http://127.0.0.1:8080 | Node.js 22+ | URL oder Header, volle App |
| **CLI**: `node bin/check.js https://www.example.ch` | Node.js 22+ | URL; Ausgabe als Markdown, mit `--json` als JSON |

Warum GitHub Pages keine URL prüfen kann: Pages hostet nur statische Dateien, und ein Browser darf die Header fremder Domains nicht lesen (CORS). Dafür gibt es den Header-Modus und den Actions-Workflow.

## Prüflogik (Ampel)

Gelesen werden nur Signale, die der Server jedem Besucher schickt: `X-Powered-By`, `Server`, Session-Cookies (`PHPSESSID` usw.), CMS-Header, `<meta name="generator">` sowie CDN-Header. Alle Weiterleitungen werden mitgelesen, die **schlechteste** gesehene Version bestimmt das Ergebnis.

| Ampel | Wann |
| --- | --- |
| 🔴 **Verdacht auf Verwundbarkeit** | Upstream-Version unter dem Fix-Release, Distributionspaket unter dem Fix-Paket oder Distribution ohne Fix. Ebenso ein EOL-Zweig (8.1 und älter) ohne Hinweis auf einen Distributions-Build. |
| 🟠 **Unbestimmt, lokal prüfen** | PHP erkannt, aber keine Version sichtbar (z.B. `expose_php=Off`). Oder Version unter dem Fix-Stand bei einem Distributions-Build (Ubuntu, Debian, RHEL-Familie), der den Fix zurückportiert haben kann. Oder der Fix-Stand der Distribution ist im Tool noch nicht bestätigt. |
| 🟢 **Wahrscheinlich gepatcht** | Version auf oder über dem Fix-Release bzw. Fix-Paket |
| ⚪ **Keine PHP-Hinweise** | Nichts deutet auf PHP hin. Das ist ausdrücklich **kein** «nicht betroffen». |

Builds von `deb.sury.org` werden wie Upstream behandelt, weil sie keine Backports enthalten. Jedes Ergebnis enthält Begründung, nächste Schritte und Hinweise, z.B. auf ein erkanntes CDN, das den Origin verdeckt.

### Fix-Daten pflegen

Alle Versionsstände stehen in [`webapp/model/fixdata.json`](webapp/model/fixdata.json), mit Datum und Quelle. Jeder Distributionseintrag hat einen Status:

- `fixed`: gefixte Paketversion bekannt, Vergleich nach dpkg-Regeln
- `no-fix`: die Distribution hat bestätigt noch keinen Fix → 🔴
- `unconfirmed`: Fix-Stand in diesem Tool noch nicht verifiziert → 🟠

Stand 2026-10-21: Debian 13 gefixt mit `8.4.27-1~deb13u1` (DSA-6574-1). Debian 12 noch ohne Fix. Ubuntu ist noch nicht bestätigt; der Ubuntu-Tracker zeigt «Needs evaluation». Neue Advisories nur aus Primärquellen übernehmen (Distribution, php.net) und `asOf` anpassen.

## Prüfung auf dem Server

```bash
# Debian/Ubuntu: installierte PHP-Pakete und Versionen
dpkg -l 'php*' | awk '/^ii/{print $2, $3}'
# Ubuntu: steht der CVE im Changelog des FPM-Pakets?
zgrep -E 'CVE-2026-10961[89]' /usr/share/doc/php8.3-fpm/changelog.Debian.gz
# RHEL/Alma/Rocky
rpm -qa 'php*'; dnf updateinfo list --security | grep php
# Läuft der neue Code? Startzeit des FPM-Masters mit der Paketinstallation vergleichen
ps -o lstart= -p "$(pgrep -o php-fpm)"
```

`php -v` reicht nicht: Distributionen backporten Fixes oft in die alte Versionsnummer, z.B. meldet Ubuntu 24.04 weiterhin 8.3.6. Massgeblich sind auch die Einstellungen des FPM-Pools bzw. von mod_php, nicht die CLI-`php.ini`. Nach dem Update PHP-FPM bzw. Apache neu starten.

Mitigation, falls der Patch nicht sofort geht. Sie ist laut PHP-Projekt unvollständig:

- `memory_limit=-1` so setzen, dass Anwendungen es nicht überschreiben können (`php_admin_value`), und Request-Grössen am Webserver begrenzen
- `session.upload_progress.enabled=0` setzen
- unter PHP 8.5 zusätzlich `fatal_error_backtraces=0`
- danach alle Worker neu starten

## Sicherheit des Checkers

- **Passiv:** Pro Hop ein normaler `GET` wie ein Browser, kein Exploit-Versuch. Gelesen werden höchstens 256 KB, nach 8 Sekunden ist Schluss, maximal 3 Weiterleitungen.
- **SSRF-Schutz:**
  - nur Ports 80 und 443, keine Zugangsdaten in URLs
  - keine privaten, Loopback-, Link-Local- oder Metadata-Adressen, auch nicht in IPv6-Verpackung (mapped, NAT64, 6to4, Teredo)
  - Die Adressprüfung läuft im DNS-Lookup der Verbindung selbst (kein DNS-Rebinding) und bei jeder Weiterleitung neu.
- **TLS:** Zertifikate werden immer geprüft. Spricht ein Server nur veraltetes TLS, folgt ein zweiter Versuch im Kompatibilitätsmodus, und das Ergebnis weist darauf hin.
- **API:**
  - Rate-Limit pro Client
  - nur `application/json`
  - strikte CSP (`script-src 'self'`), OpenUI5 wird selbst gehostet, kein CDN
- **Actions-Workflow:** Eingaben gehen nur über Umgebungsvariablen in das Skript (keine Script-Injection), Rechte sind auf `contents: read` beschränkt.

## Konfiguration (Server)

| Variable | Standard | Bedeutung |
| --- | --- | --- |
| `PORT` | `8080` | Port |
| `HOST` | `127.0.0.1` | Bind-Adresse; für Container `0.0.0.0` |
| `ALLOWED_HOSTS` | leer = alle öffentlichen | Komma-Liste erlaubter Domains inkl. Subdomains |
| `RATE_LIMIT` | `20` | Prüfungen pro Client und Minute |
| `TRUST_PROXY` | `0` | `1` = Client-IP aus `X-Forwarded-For` (nur hinter eigenem Reverse-Proxy) |

## Entwicklung

```bash
npm install     # UI5 Tooling (einzige Dependency, nur zum Bauen)
npm test        # Engine, SSRF-Schutz, Fetcher, API, CLI
npm start       # baut dist/ und startet den Server
```

```
webapp/engine/php2shell.js   Prüf-Engine (Browser + Node, ohne I/O)
webapp/model/fixdata.json    Fix-Stände mit Quellen
webapp/                      OpenUI5-App (Horizon, Deutsch/Englisch)
server/                      Fetcher, SSRF-Schutz, HTTP-Server
bin/check.js                 CLI, auch für GitHub Actions
.github/workflows/           CI + Pages-Deployment, Check-Workflow
```

## Definition of Done

- [x] Testmatrix grün:
  - offizielle Images vor und nach dem Fix
  - Ubuntu-Paket, Ubuntu ohne Suffix
  - Debian 12/13
  - RHEL
  - sury-Builds
  - EOL
  - `expose_php=Off`
  - LiteSpeed
  - CDN
  - statische Seite
- [x] Distro-Backports erzeugen keine falschen 🔴-Alarme, sondern 🟠 mit Begründung.
- [x] Nie «nicht betroffen». Jedes Ergebnis hat Begründung, nächsten Schritt und den Hinweis auf die Grenzen der Remote-Prüfung.
- [x] SSRF-Tests: Metadata-IP, Loopback, `localhost`, Redirect nach intern, Port, Zugangsdaten, IPv6-Varianten
- [x] UI geprüft:
  - Deutsch und Englisch
  - hell und dunkel
  - Phone-Breite
  - mit und ohne Server-Komponente
  - keine CSP-Verstösse
- [x] Fix-Daten mit Quelle und Stand, Texte in beiden Sprachen vollständig (Test)
- [ ] Ubuntu-Fix-Pakete bestätigen, sobald Canonical sie veröffentlicht

## Lizenz

[MIT](LICENSE)
