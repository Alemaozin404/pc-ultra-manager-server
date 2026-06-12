# PC Ultra Manager Server

Servidor FastAPI para o PC Ultra Manager / Gamer Boost, com login, premium, beta fechado, Mercado Pago PIX e loja de temas conectada ao app.

## Render

Este projeto já vem com `render.yaml` pronto para criar:

- Web Service Python.
- PostgreSQL do Render.
- `DATABASE_URL` conectado automaticamente ao PostgreSQL.
- Variáveis obrigatórias do admin, JWT e Mercado Pago.

Build Command:

```bash
pip install -r requirements.txt
```

Start Command:

```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

## Variáveis obrigatórias em produção

Configure no Render em **Environment**:

```env
APP_ENV=production
DATABASE_URL=postgresql://...
JWT_SECRET=uma-chave-grande-e-secreta-com-mais-de-32-caracteres
ADMIN_USERNAME=admin
ADMIN_PASSWORD=sua-senha-forte-com-mais-de-12-caracteres
SESSION_DAYS=30
CORS_ORIGINS=https://pc-ultra-manager-server.onrender.com,https://alemaozin404.github.io
```

Em produção, o servidor agora bloqueia inicialização se:

- `DATABASE_URL` estiver ausente.
- `DATABASE_URL` for SQLite.
- `ADMIN_PASSWORD` estiver ausente, fraca ou padrão.
- `JWT_SECRET` estiver ausente, fraco ou padrão.
- `PUBLIC_BASE_URL` não for HTTPS.
- `PAYMENT_PROVIDER` for inválido.

## Mercado Pago PIX automático

Variáveis obrigatórias no Render para pagamento automático:

```env
PAYMENT_PROVIDER=mercadopago
MERCADOPAGO_ACCESS_TOKEN=APP_USR-SEU_TOKEN_DE_PRODUCAO
MERCADOPAGO_WEBHOOK_SECRET=SUA_ASSINATURA_SECRETA_DO_WEBHOOK
MERCADOPAGO_WEBHOOK_TOLERANCE_SECONDS=900
PUBLIC_BASE_URL=https://pc-ultra-manager-server.onrender.com
MERCADOPAGO_PAYER_EMAIL_DOMAIN=pcultramanager.com.br
```

Webhook no Mercado Pago:

```txt
https://pc-ultra-manager-server.onrender.com/payments/mercadopago/webhook
```

Evento principal necessário: `payment` / Pagamentos.

Fluxo:

1. O app cria pedido.
2. O servidor cria cobrança PIX no Mercado Pago.
3. O app mostra QR Code/Copia e Cola.
4. O Mercado Pago chama o webhook.
5. O servidor valida assinatura quando o secret existe.
6. O servidor consulta o pagamento na API oficial.
7. O servidor entrega o plano somente se `external_reference`, `payment_id`, método PIX e valor estiverem corretos.

## Correção importante do Mercado Pago

O Mercado Pago exige `payer.email` em formato válido. Como o app usa nome de usuário em vez de e-mail real, o servidor gera um e-mail técnico por usuário usando `MERCADOPAGO_PAYER_EMAIL_DOMAIN`.

Exemplo:

```env
MERCADOPAGO_PAYER_EMAIL_DOMAIN=pcultramanager.com.br
```

Não use domínios `.local`, porque o Mercado Pago pode rejeitar o pagamento com erro de e-mail inválido.


## Loja de temas conectada ao app

O servidor agora suporta um site separado vendendo temas com o mesmo login do app.

Fluxo correto:

```txt
Site de temas -> servidor -> Mercado Pago PIX -> banco PostgreSQL -> app principal
```

O site não guarda token do Mercado Pago. Ele apenas faz login, lista os temas, cria o pedido e mostra QR Code/PIX Copia e Cola retornados pelo servidor.

Rotas públicas/usuário:

- `GET /themes/store` - lista temas ativos da loja.
- `GET /themes/my` - mostra temas comprados/liberados para o usuário logado.
- `POST /themes/purchase` - cria pedido de compra de tema e retorna PIX quando Mercado Pago está ativo.
- `GET /themes/orders/{order_id}/payment-status` - verifica pagamento do pedido de tema e libera automaticamente se aprovado.

Rotas admin:

- `GET /admin/themes`
- `POST /admin/themes/create`
- `POST /admin/themes/give`
- `POST /admin/themes/remove`
- `GET /admin/theme-orders`
- `POST /admin/theme-orders/approve`
- `POST /admin/theme-orders/cancel`

Temas iniciais criados automaticamente quando ainda não existem no banco:

- `windows_11_pro_glass`
- `cinema_dark_luxury`
- `liquid_glass_pro`

Quando o Mercado Pago aprova um pagamento com `external_reference=theme:{order_id}`, o webhook valida o pagamento e salva o tema em `user_themes`. Depois o app só precisa chamar `GET /themes/my` para desbloquear o tema.

## Desenvolvimento local

Para rodar localmente sem PostgreSQL:

```env
APP_ENV=development
DATABASE_URL=
PAYMENT_PROVIDER=manual
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123456
JWT_SECRET=dev-only-change-this-secret-local-000000000000
CREATE_TEST_KEY=true
```

Depois rode:

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

## Rotas principais

- `GET /health`
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/recover`
- `GET /me`
- `POST /license/activate`
- `GET /license/status`
- `POST /orders/create`
- `GET /orders/my`
- `GET /orders/{order_id}/payment-status`
- `POST /payments/mercadopago/webhook`
- `GET /themes/store`
- `GET /themes/my`
- `POST /themes/purchase`
- `GET /themes/orders/{order_id}/payment-status`
- `GET /admin/themes`
- `POST /admin/themes/create`
- `POST /admin/themes/give`
- `POST /admin/themes/remove`
- `GET /admin/theme-orders`
- `POST /admin/theme-orders/approve`
- `POST /admin/theme-orders/cancel`
- `POST /admin/keys/create`
- `GET /admin/keys`
- `POST /admin/keys/revoke`
- `GET /admin/users`
- `POST /admin/users/change-plan`
- `GET /admin/orders`
- `POST /admin/orders/approve`
- `POST /admin/orders/cancel`
- `POST /logs/create`
- `GET /admin/logs`

## E-mail de comprovante dos temas

Depois que um pagamento de tema é aprovado, o servidor pode enviar automaticamente um e-mail para o comprador com:

- comprovante para emergências;
- número do pedido;
- ID do pagamento Mercado Pago;
- tema comprado/assinado;
- valor pago;
- tutorial de ativação no app;
- data da ativação;
- validade da assinatura, quando o tema for assinatura, como Matrix Effect.

Para ativar no Render, configure:

```env
EMAIL_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_USERNAME=seuemail@gmail.com
SMTP_PASSWORD=sua_senha_de_app_ou_smtp
SMTP_FROM_EMAIL=seuemail@gmail.com
SMTP_FROM_NAME=PC Ultra Manager
SMTP_SUPPORT_EMAIL=seuemail@gmail.com
SMTP_USE_SSL=auto
SMTP_USE_STARTTLS=auto
```

Se `EMAIL_ENABLED=false` ou SMTP não estiver configurado, a compra continua funcionando normalmente, mas o servidor registra que o comprovante por e-mail não foi enviado.
