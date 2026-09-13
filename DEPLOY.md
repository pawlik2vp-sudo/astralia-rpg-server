# Uruchomienie serwera "Online" (czat + ranking)

`server.js` to zwykły plik Node.js **bez żadnych zależności zewnętrznych** —
nie trzeba `npm install`, wystarczy sam Node (wersja 18+).

## 1. Szybki test na własnym komputerze

```
node server.js
```

Serwer wystartuje na `http://localhost:8787`. W grze, w zakładce **Online**,
wpisz jako adres `http://localhost:8787` i dowolny nick, kliknij "Połącz".
To zadziała tylko na TYM SAMYM komputerze (localhost = "ja sam") — dobre do
sprawdzenia, że wszystko działa, zanim wystawisz serwer na świat.

Żeby przetestować z kimś w tej samej sieci Wi-Fi (bez wystawiania na
internet), zamiast `localhost` użyj adresu IP swojego komputera w sieci
lokalnej, np. `http://192.168.1.23:8787` (adres sprawdzisz np. przez
`ipconfig` na Windows albo `ifconfig`/`ip addr` na Mac/Linux).

## 2. Żeby grało więcej osób spoza Twojej sieci

Do tego serwer musi działać 24/7 gdzieś w internecie, a nie tylko na Twoim
komputerze. Masz dwie drogi:

**A. Hosting w chmurze (zalecane, zwykle darmowe dla małego ruchu)**
Szukaj hostingu, który potrafi uruchomić zwykłą aplikację Node.js (np.
Render, Railway, Fly.io, Glitch, Replit — oferta i darmowe limity tych
usług zmieniają się dość często, więc sprawdź aktualne warunki, zanim
wybierzesz). Niezależnie od wybranego dostawcy, ustawienia są zawsze takie
same, bo to zwykły plik Node:
- Start command: `node server.js`
- Brak kroku "build" — nie ma czego kompilować.
- Serwer sam odczytuje port z `process.env.PORT`, więc zadziała z portem,
  jaki przydzieli dostawca.
- Zwykle wystarczy wgrać/połączyć folder `server/` (repozytorium Git albo
  wgranie plików bezpośrednio, zależnie od dostawcy).

Po wdrożeniu dostawca poda Ci publiczny adres (np.
`https://twoja-nazwa.up.railway.app`) — właśnie ten adres wpisujesz w grze.

Daj znać, jakiego dostawcę wybierzesz — pomogę przejść przez konkretne
kroki na żywo, bo dokładny interfejs bywa różny.

**B. Twój własny komputer + tunel (szybkie, ale komputer musi być cały czas
włączony i online)**
Narzędzie takie jak Cloudflare Tunnel albo ngrok potrafi "wystawić" serwer
działający lokalnie pod publicznym adresem, bez konfigurowania routera. To
dobre do szybkich testów ze znajomymi, gorsze na stałe (adres zwykle się
zmienia przy restarcie, a gra musi działać na Twoim sprzęcie).

## 3. Dane graczy

Ranking i czat trzymane są w plikach `server/data/leaderboard.json` i
`server/data/chat.json` obok `server.js` — tworzą się same przy pierwszym
uruchomieniu. Część darmowych hostingów kasuje pliki przy każdym nowym
wdrożeniu (tzw. "ephemeral filesystem") — jeśli zależy Ci na trwałości
rankingu między wdrożeniami, szukaj opcji z "persistent disk"/"volume", albo
daj znać, a pomogę przepiąć zapis na bazę danych.

## 4. Ograniczenia, o których warto wiedzieć

- To NIE są prawdziwe konta — nick nie jest niczym chroniony. Dla grupy
  znajomych to nieszkodliwe, ale nie nadaje się na publiczną, dużą grę.
- Ranking i czat to jedyne, co jest "wspólne". Same postacie, ekwipunek i
  walka nadal liczą się lokalnie u każdego gracza z osobna — to NIE jest
  wspólny świat, w którym widzicie się nawzajem na mapie.
- Jeśli grę kiedyś wystawisz na stronie https, a serwer zostanie na http
  (bez szyfrowania), przeglądarka może zablokować połączenie
  ("mixed content"). Większość darmowych hostingów daje https automatycznie,
  więc zwykle nie jest to problem — ale warto o tym pamiętać.
