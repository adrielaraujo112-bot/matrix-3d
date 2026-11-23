# Matrix 3D - Cloudflare Pages

Este pacote preserva o `index.html` original e adapta o endpoint de estado para Cloudflare Pages Functions.

## Estrutura

- `index.html`: interface original, com endpoint atualizado para `/api/matrix-state`.
- `functions/api/matrix-state.js`: função Cloudflare Pages para login administrativo, leitura e gravação do estado no Supabase.

## Configuração necessária na Cloudflare

No projeto Pages `matrix-3d`, abra **Settings > Variables and Secrets** e cadastre no ambiente **Production**:

- `SUPABASE_URL` (valor: URL do projeto Supabase)
- `SUPABASE_SECRET_KEY` (valor: chave secreta/service-role usada pelo backend; cadastrar como Secret/Encrypt)
- `MATRIX_ADMIN_TOKEN` (valor: uma senha administrativa forte e exclusiva; cadastrar como Secret/Encrypt)

Não coloque esses valores no HTML, no GitHub, nem em mensagens ou capturas de tela. Se uma chave secreta já foi compartilhada em local público, faça a rotação no Supabase.

Depois de adicionar os secrets, faça um novo deploy para que a Function receba as variáveis.

## GitHub

Envie/substitua os arquivos mantendo exatamente esta estrutura na raiz do repositório:

- `index.html`
- `functions/api/matrix-state.js`

A pasta `functions` deve estar na raiz do projeto (não dentro de `netlify` nem dentro de uma pasta de build).

O diretório `netlify` antigo pode ser mantido temporariamente para referência, mas não é usado pelo Cloudflare Pages.

## Build settings do Pages

- Framework preset: None
- Build command: vazio (ou `exit 0` se o painel exigir um comando)
- Build output directory: `/` ou `.` conforme a validação do painel
- Root directory: vazio

## Testes depois do deploy

1. Abrir `https://SEU-PROJETO.pages.dev/` e confirmar que o Matrix 3D carrega.
2. Abrir `https://SEU-PROJETO.pages.dev/api/matrix-state`. Deve responder JSON (ou erro de configuração até cadastrar os secrets), nunca uma página 404.
3. Testar login ADM.
4. Testar leitura e gravação do estado, manutenção global e cores.
5. Só compartilhar com clientes depois de confirmar todos os testes.

## Observações

- A função usa Web Crypto, `fetch` e `context.env`, compatíveis com o runtime de Pages Functions.
- A gravação pressupõe que a tabela `matrix3d_state` exista no Supabase, que tenha a coluna `id` com valor global `global`, a coluna `payload` e a coluna `updated_at`, e que a chave backend tenha permissão para acessar a tabela.
- Este pacote não contém nenhum segredo. Os valores devem ser configurados diretamente no painel da Cloudflare.
