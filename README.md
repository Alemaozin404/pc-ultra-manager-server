# PC Ultra Manager Server

Servidor FastAPI para o PC Ultra Manager / Gamer Boost.

## Render

Build Command:

```bash
pip install -r requirements.txt
```

Start Command:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

## Environment

Configure no Render:

```env
DATABASE_URL=postgresql://...
JWT_SECRET=uma-chave-grande-e-secreta
ADMIN_USERNAME=admin
ADMIN_PASSWORD=sua-senha-forte
SESSION_DAYS=30
CORS_ORIGINS=*
PYTHON_VERSION=3.11.9
```

## Rotas principais

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/recover`
- `GET /me`
- `POST /license/activate`
- `GET /license/status`
- `POST /admin/keys/create`
- `GET /admin/keys`
- `POST /admin/keys/revoke`
- `GET /admin/users`
- `POST /admin/users/change-plan`
- `POST /logs/create`
- `GET /admin/logs`


## Mercado Pago PIX automático

Variáveis obrigatórias no Render para pagamento automático:

```env
PAYMENT_PROVIDER=mercadopago
MERCADOPAGO_ACCESS_TOKEN=APP_USR-SEU_TOKEN-DE-PRODUCAO
MERCADOPAGO_WEBHOOK_SECRET=SUA_ASSINATURA_SECRETA
MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS=600
PUBLIC_BASE_URL=https://pc-ultra-manager-server.onrender.com
```

Webhook no Mercado Pago:

```txt
https://pc-ultra-manager-server.onrender.com/payments/mercadopago/webhook
```

Evento principal necessário: Pagamentos. Com `MERCADOPAGO_WEBHOOK_SECRET` configurado, o servidor valida o header `x-signature` antes de consultar e entregar o pagamento.

Fluxo: o app cria pedido, o servidor cria cobrança PIX no Mercado Pago, o app mostra QR Code/Copia e Cola, o webhook confirma pagamento e o servidor entrega o plano automaticamente.


### Correção importante do Mercado Pago

O Mercado Pago exige `payer.email` em formato válido. Como o app usa nome de usuário em vez de e-mail real, o servidor gera um e-mail técnico por usuário usando `MERCADOPAGO_PAYER_EMAIL_DOMAIN`.

No Render, pode deixar:

```env
MERCADOPAGO_PAYER_EMAIL_DOMAIN=pcultramanager.com.br
```

Não use domínios `.local`, porque o Mercado Pago rejeita e retorna erro `payer.email must be a valid email`.
