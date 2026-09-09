# DTLab Next.js frontend

Frontend alternativo per la DTLab Control Center API. Espone Command Center,
inventario, topologia, rischio, eventi, vulnerabilità, baseline, segnali, ticket,
evidenze, scenari di attacco, Digital Twin e compliance.

## Avvio

```bash
cp .env.example .env.local
npm ci
npm run dev
```

`NEXT_PUBLIC_API_BASE` deve puntare alla FastAPI DTLab. Il login accetta soltanto
token configurati sul backend attraverso `DTLAB_API_TOKENS`; il frontend non contiene
token dimostrativi o credenziali predefinite.

Per lint e build:

```bash
npm run lint
npm run build
```
