# Investigador Digital

Aplicação Flask com autenticação, painel administrativo, dashboard e geração de relatórios em PDF.

## Requisitos

- Python 3.11+
- PostgreSQL para produção
- Variáveis de ambiente configuradas

## Execução local

1. Crie e ative um ambiente virtual.
2. Instale as dependências com `pip install -r requirements.txt`.
3. Copie `.env.example` para `.env` e ajuste os valores.
4. Para desenvolvimento local, use `APP_ENV=development` e `ALLOW_SQLITE=true`.
5. Inicie com `python main.py`.

## Produção

- Defina `APP_ENV=production`.
- Defina `SECRET_KEY` com valor forte.
- Defina `DATABASE_URL` para PostgreSQL.
- Defina `DEFAULT_ADMIN_USERNAME` e `DEFAULT_ADMIN_PASSWORD` apenas para bootstrap inicial seguro.
- Use `gunicorn --bind 0.0.0.0:$PORT main:app` ou o [Procfile](/D:/Aplicativo%20teste/16Ago2025/Procfile).

## Deploy em plano gratuito

O caminho mais simples é usar um serviço com Python + PostgreSQL gerenciado.

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn --bind 0.0.0.0:$PORT main:app`
- Variáveis mínimas: `APP_ENV`, `SECRET_KEY`, `DATABASE_URL`, `PORT`

## Deploy no Firebase

Este projeto esta configurado para rodar no Firebase Hosting com rewrite para uma Cloud Function Python chamada `webapp`.

1. Instale e autentique a Firebase CLI:

   ```bash
   npm install -g firebase-tools
   firebase login
   ```

2. Associe este diretorio ao seu projeto Firebase:

   ```bash
   firebase use --add
   ```

   Se preferir, use `--project SEU_PROJECT_ID` nos comandos de deploy.

3. Crie um arquivo `.env.SEU_PROJECT_ID` na raiz do projeto com as variaveis de producao:

   ```env
   APP_ENV=production
   SECRET_KEY=SUA_SECRET_KEY_FORTE
   DATABASE_URL=SUA_DATABASE_URL_POSTGRES
   DEFAULT_ADMIN_USERNAME=admin_inicial
   DEFAULT_ADMIN_PASSWORD=SENHA_FORTE_INICIAL
   SESSION_COOKIE_SECURE=true
   REMEMBER_COOKIE_SECURE=true
   LOG_LEVEL=INFO
   ```

   Use o modelo [.env.firebase.example](/D:/Aplicativo%20teste/16Ago2025/.env.firebase.example). Nao envie o `.env.SEU_PROJECT_ID` para repositorio publico.

4. Teste localmente com os emuladores:

   ```bash
   firebase emulators:start
   ```

5. Publique:

   ```bash
   firebase deploy --only functions,hosting
   ```

Depois do deploy, o app ficara disponivel em `https://SEU_PROJECT_ID.web.app`.

## Observações

- SQLite ficou limitado a desenvolvimento/local.
- O projeto usa [pyproject.toml](/D:/Aplicativo%20teste/16Ago2025/pyproject.toml) e [requirements.txt](/D:/Aplicativo%20teste/16Ago2025/requirements.txt); mantenha os dois alinhados se optar por usar ambos.
