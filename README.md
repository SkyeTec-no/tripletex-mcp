# Tripletex MCP Server

En open source [MCP-server](https://modelcontextprotocol.io/) som lar AI-assistenter (Claude, Cursor, osv.) jobbe direkte mot Tripletex sitt regnskapssystem.

Bygd og vedlikeholdt av [CWV Ventures AS](https://cwv.no).

## Trenger du hjelp til implementering?
Kontakt meg på carl@cwv.no.

## Hva kan den gjøre?

| Kategori | Verktøy | Beskrivelse |
|---|---|---|
| **Timeføring** | `search_projects` | Søk etter prosjekter (filtre: `isClosed`, `customerId`, `projectManagerId`, `number`) |
| | `search_activities` | Søk etter aktiviteter |
| | `search_time_entries` | Hent timeoppføringer for en periode |
| | `create_time_entry` | Logg timer (krever `employeeId` + prosjekt/aktivitet) |
| **Faktura** | `create_order` | Opprett ordre med Tripletex-felt (`orderLines`, `count`, priser) |
| | `invoice_order` | Fakturer eksisterende ordre |
| | `create_invoice` | Ordre + faktura i ett steg |
| | `search_invoices` | Søk utgående fakturaer (påkrevd datointervall) |
| | `get_invoice` | Hent én faktura (valgfri `fields`) |
| | `search_supplier_invoices` | Søk leverandørfakturaer (påkrevd datointervall) |
| | `search_orders` | Søk ordrer i en periode (`isClosed=false` = åpne ordrer) |
| **Kunder & leverandører** | `search_customers` | Søk kunder |
| | `create_customer` | Opprett kunde |
| | `update_customer` | Oppdater kunde |
| | `search_suppliers` | Søk leverandører |
| | `create_supplier` | Opprett leverandør |
| **Produkter** | `search_products` | Søk produkter |
| | `create_product` | Opprett produkt |
| **Regnskap** | `search_accounts` | Søk i kontoplan |
| | `search_vat_types` | Liste MVA-typer |
| | `search_vouchers` | Søk bilag |
| | `get_voucher` | Hent bilag |
| | `create_voucher` | Opprett bilag (`amountGross` per linje) |
| **Utility** | `whoami` | Info om innlogget bruker/selskap |
| | `search_employees` | Søk ansatte (filtre: `lastName`, `employeeNumber`, `departmentId`) |

### `fields` og paginering

Alle søkeverktøyene tar Tripletex sin egen `fields`-parameter, som sendes rett videre til API-et. Uten den returnerer Tripletex bare standardfeltene, og nøstede objekter kommer tilbake som `{id, url}` uten navn:

```
search_projects  { isClosed: false, fields: "id,number,name,customer(id,name)" }
search_invoices  { invoiceDateFrom: "2026-01-01", invoiceDateTo: "2026-12-31", fields: "*" }
```

`from` og `count` styrer paginering. Tripletex tillater maks 1000 rader per kall.

## Kom i gang

### 1. Hent API-nøkler fra Tripletex

Det finnes to måter å autentisere på. Lager du en integrasjon til ditt eget selskap, bruk den første — da slipper du consumer token helt.

**A) Intern integrasjon (ett selskap eller konsern) — anbefalt**

En bruker med admin-rettigheter oppretter en JWT under **Selskap → API-tokens** i Tripletex. Hemmeligheten vises bare én gang, så ta vare på den med en gang. Sett den som `TRIPLETEX_JWT`. Ingen consumer token, ingen søknad til Tripletex.

Krever at Integrasjoner-modulen er aktiv på kontoen.

**B) Kommersiell integrasjon (flere kunder)**

- **Consumer token** — søk om produksjonstilgang via [developer.tripletex.no](https://developer.tripletex.no). Godkjenning tar typisk 2–3 uker. For testing kan du opprette en gratis testkonto med egne tokens.
- **Employee token** — opprettes av hver sluttkunde i Tripletex under **Innstillinger → Integrasjoner → API-tilgang**.

Settes som `TRIPLETEX_CONSUMER_TOKEN` + `TRIPLETEX_EMPLOYEE_TOKEN`.

> Tokens for testmiljøet (`api-test.tripletex.tech`) virker ikke i produksjon (`tripletex.no`), og omvendt.

### 2. Installer

```bash
git clone https://github.com/cwv-ventures/tripletex-mcp.git
cd tripletex-mcp
npm install
npm run build
```

### 3. Koble til Claude Desktop

Legg til følgende i Claude Desktop sin konfigurasjonsfil:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** `~/.config/claude-desktop/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "tripletex": {
      "command": "node",
      "args": ["/absolutt/sti/til/tripletex-mcp/dist/index.js"],
      "env": {
        "TRIPLETEX_JWT": "din-jwt-hemmelighet"
      }
    }
  }
}
```

### 4. Testmiljø

For å bruke Tripletex sitt testmiljø (`api-test.tripletex.tech`) istedenfor produksjon, legg til:

```json
"TRIPLETEX_ENV": "test"
```

i `env`-blokken.

## Hvordan autentisering fungerer

Serveren håndterer alt automatisk. Ved første kall opprettes en session token:

- **Med `TRIPLETEX_JWT`:** `POST /v2/token/session/:createFromRefreshToken` med `{ refreshToken, ttlSeconds }`. Levetiden er 8 timer som standard (Tripletex' tak er 28800 s), og kan overstyres med `TRIPLETEX_SESSION_TTL_SECONDS`.
- **Med consumer + employee token:** `PUT /v2/token/session/:create`. Disse utløper ved midnatt CET.

Session token fornyes automatisk når den utløper, og ved 401 forsøkes kallet på nytt med fersk token. Alle API-kall bruker Basic Auth med brukernavn `0` og session token som passord.

Du trenger ikke tenke på dette — bare sett miljøvariablene.

### Miljøvariabler

| Variabel | Hva |
|---|---|
| `TRIPLETEX_JWT` | JWT-hemmelighet fra **Selskap → API-tokens** (intern integrasjon) |
| `TRIPLETEX_CONSUMER_TOKEN` | Consumer token (kommersiell integrasjon) |
| `TRIPLETEX_EMPLOYEE_TOKEN` | Employee token (kommersiell integrasjon) |
| `TRIPLETEX_ENV` | `test` for `api-test.tripletex.tech`. Utelates i produksjon |
| `TRIPLETEX_SESSION_TTL_SECONDS` | Levetid på session token i JWT-flyten. Standard `28800` (8 t, Tripletex' maks) |
| `MCP_TRANSPORT` | `http` for Railway/remote (endepunkt `/mcp`). Standard `stdio` |
| `PORT` | Port i HTTP-modus. Settes automatisk av Railway |

#### SkyeTec-fork: OAuth, innlogging og skrivetilgang

| Variabel | Hva |
|---|---|
| `OAUTH_ENC_KEY` | 32 tilfeldige bytes, base64. Slår på OAuth-fasaden og forsegler tokens (AES-256-GCM). **Uten denne nekter HTTP-transporten å starte** |
| `PUBLIC_BASE_URL` | Utstederen (issuer) — der `/authorize`, `/token` og `/register` ligger. Påkrevd når OAuth er på |
| `PUBLIC_RESOURCE_URL` | Settes kun når MCP-endepunktet ligger under en annen sti enn issueren (sti-ruteren på `mcp.skyetec.ai`). Utelatt → samme som `PUBLIC_BASE_URL` |
| `OAUTH_ALLOWED_REDIRECTS` | Kommaseparerte redirect-URI-er som `/register` godtar. Loopback er alltid tillatt |
| `TRIPLETEX_CONSUMER_TOKEN` | **Påkrevd for personlige nøkler.** Serverens egen consumer token. Den er hemmelig og skal aldri sendes til nettleseren — kun employee-tokenet kommer fra brukeren |
| `TRIPLETEX_CONSUMER_NAME` | Applikasjonsnavnet brukeren må oppgi i Tripletex når nøkkelen opprettes. Vises på innloggingssiden |
| `MCP_READ_ONLY` | `true` → kun leseverktøy registreres, og skills slås av |
| `MCP_WRITE_TOOLS` | Kommaseparert liste over skriveverktøy som slippes gjennom i tillegg til leseflaten |
| `TRIPLETEX_MCP_STATE_DSN` | Postgres-DSN for kvitteringstabellen (`write_receipts`): `Idempotency-Key` → første resultat, bundet til kaller og verktøy. Satt → varig dedupe som overlever omstart, og en utilgjengelig database **nekter** skrivet i stedet for å kjøre det ukvittert. Usatt → in-memory, varslet på stderr ved oppstart |
| `MCP_ALLOW_UNAUTHENTICATED` | `true` → tillat HTTP uten OAuth. Da er `/mcp` helt åpent; kun for lokal utvikling |

Brukeren logger inn ved å lime inn sin **personlige nøkkel** fra eget ansattkort → **API-tilganger**
(en base64-verdi som begynner med `eyJ`). Serveren veksler den mot en Tripletex-sesjon sammen med sin
egen consumer token, og forsegler den kryptert i tilgangsnøkkelen — den lagres aldri i klartekst.
`tlxr_`-tokens fra **Selskap → API-tokens** virker fortsatt; serveren kjenner igjen formen og velger
riktig endepunkt selv.

Tilgangen er avgrenset av Tripletex: en nøkkel kan aldri ha flere rettigheter enn den ansatte den er
opprettet på.

### Nøkler per kall (HTTP-transport)

I HTTP-modus kan klienten sende nøklene som headere i stedet for at de ligger i miljøet. Da holder ikke endepunkt-URL-en alene for å lese regnskapet, og én deploy kan betjene flere selskaper:

| Header | Tilsvarer |
|---|---|
| `X-Tripletex-Jwt` | `TRIPLETEX_JWT` |
| `X-Tripletex-Consumer-Token` | `TRIPLETEX_CONSUMER_TOKEN` |
| `X-Tripletex-Employee-Token` | `TRIPLETEX_EMPLOYEE_TOKEN` |
| `X-Tripletex-Env` | `TRIPLETEX_ENV` |

Headerne leses når MCP-sesjonen opprettes (`initialize`), og gjelder for resten av sesjonen. Sendes ingen av dem, brukes miljøvariablene.

## Eksempler på bruk

Når MCP-serveren er koblet til Claude, kan du si ting som:

> "Logg 7.5 timer på prosjekt Konsulentbistand i dag"

Claude finner prosjektet, velger riktig aktivitet, og oppretter timeoppføringen.

> "Vis alle fakturaer til Nordvik Bygg fra mars 2026"

Claude søker kunder, finner riktig ID, og henter fakturaene.

> "Opprett ny kunde Havbruk Nord AS med org.nr 912 345 678"

Claude oppretter kunden direkte i Tripletex.

> "Hvilke bilag ble ført forrige uke?"

Claude søker bilag med datofilter og viser en oversikt.

## Teknisk

- **Produktspesifikasjon (rebuild):** [docs/PRD-Tripletex-MCP-Rebuild.md](docs/PRD-Tripletex-MCP-Rebuild.md) beskriver mål-API, verktøy og felter mot Tripletex v2.
- **Runtime:** Node.js 18+
- **Språk:** TypeScript
- **Avhengigheter:** Kun `@modelcontextprotocol/sdk`
- **Transport:** stdio (standard MCP-protokoll)
- **API:** Tripletex REST API v2

## Bidra

Pull requests er velkomne! Åpne gjerne et issue hvis du har forslag til nye verktøy eller forbedringer.

## Lisens

MIT — se [LICENSE](LICENSE) for detaljer.
