const express = require('express');
const bcrypt = require('bcryptjs');
const { getDB } = require('./database');
const { login, authenticateToken, requireAdmin, changePassword } = require('./auth');

const app = express();
app.use(express.json());

// Helper para validação estrita de e-mail e telefone
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  const cleaned = phone.replace(/\D/g, '');
  return cleaned.length >= 10 && cleaned.length <= 11;
}

// ==========================================
// ENDPOINTS DE AUTENTICAÇÃO E USUÁRIOS
// ==========================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { loginIdentifier, password } = req.body;
    const result = await login(loginIdentifier, password);
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Erro interno no servidor.' });
  }
});

app.put('/api/users/:id/password', authenticateToken, async (req, res) => {
  try {
    const targetUserId = parseInt(req.params.id, 10);
    const { newPassword } = req.body;
    const result = await changePassword(req.user, targetUserId, newPassword);
    res.json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Erro ao alterar senha.' });
  }
});

// CRUD de Usuários (Apenas ADMIN)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  const db = await getDB();
  const users = await db.all('SELECT id, username, email, role, created_at FROM users ORDER BY id DESC');
  res.json(users);
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    if (!username || !email || !password || !role) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'E-mail inválido.' });
    }

    if (!['USER', 'ADMIN'].includes(role)) {
      return res.status(400).json({ error: 'Role inválido. Use USER ou ADMIN.' });
    }

    const db = await getDB();
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await db.run(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username.trim(), email.trim().toLowerCase(), hashedPassword, role]
    );

    res.status(201).json({ id: result.lastID, username, email, role });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE constraint failed')) {
      return res.status(400).json({ error: 'Username ou E-mail já cadastrado.' });
    }
    res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
  }
});

app.delete('/api/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  const db = await getDB();
  const userId = parseInt(req.params.id, 10);

  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Não é possível excluir o próprio usuário logado.' });
  }

  await db.run('DELETE FROM users WHERE id = ?', [userId]);
  res.json({ message: 'Usuário removido com sucesso.' });
});

// ==========================================
// ENDPOINTS DE CHAMADOS (TICKETS)
// ==========================================

// Abertura de Chamado (Visão Colaborador)
app.post('/api/tickets', authenticateToken, async (req, res) => {
  try {
    const { operator_name, contact_email, contact_phone, shift, title, description } = req.body;

    if (!operator_name || !contact_email || !contact_phone || !shift || !title || !description) {
      return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
    }

    if (!isValidEmail(contact_email)) {
      return res.status(400).json({ error: 'E-mail de contato inválido.' });
    }

    if (!isValidPhone(contact_phone)) {
      return res.status(400).json({ error: 'Telefone/WhatsApp inválido. Forneça DDD + número.' });
    }

    if (!['Manhã', 'Tarde', 'Noite'].includes(shift)) {
      return res.status(400).json({ error: 'Turno inválido. Opções válidas: Manhã, Tarde, Noite.' });
    }

    const db = await getDB();
    const result = await db.run(
      `INSERT INTO tickets (user_id, operator_name, contact_email, contact_phone, shift, title, description, status) 
       VALUES (?, ?, ?, ?, ?, ?, ?, 'Aberto')`,
      [req.user.id, operator_name.trim(), contact_email.trim(), contact_phone.trim(), shift, title.trim(), description.trim()]
    );

    res.status(201).json({ id: result.lastID, message: 'Chamado aberto com sucesso.' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao criar chamado.' });
  }
});

// Listagem de Chamados (RBAC: USER vê os seus, ADMIN vê todos)
app.get('/api/tickets', authenticateToken, async (req, res) => {
  const db = await getDB();
  let tickets;

  if (req.user.role === 'ADMIN') {
    tickets = await db.all(`
      SELECT t.*, u.username as creator_username 
      FROM tickets t 
      JOIN users u ON t.user_id = u.id 
      ORDER BY t.created_at DESC
    `);
  } else {
    tickets = await db.all(`
      SELECT t.*, u.username as creator_username 
      FROM tickets t 
      JOIN users u ON t.user_id = u.id 
      WHERE t.user_id = ? 
      ORDER BY t.created_at DESC
    `, [req.user.id]);
  }

  res.json(tickets);
});

// Resolução Técnica e Atualização do Chamado (Visão Administrador)
app.put('/api/tickets/:id/resolve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const ticketId = parseInt(req.params.id, 10);
    const { status, resolution_what, resolution_how } = req.body;

    if (!resolution_what || !resolution_how) {
      return res.status(400).json({ error: 'Os campos "O que foi feito?" e "Como foi realizado?" são obrigatórios.' });
    }

    const db = await getDB();
    const ticket = await db.get('SELECT id FROM tickets WHERE id = ?', [ticketId]);

    if (!ticket) {
      return res.status(404).json({ error: 'Chamado não encontrado.' });
    }

    const newStatus = status || 'Concluído';

    await db.run(
      `UPDATE tickets 
       SET status = ?, resolution_what = ?, resolution_how = ?, updated_at = CURRENT_TIMESTAMP 
       WHERE id = ?`,
      [newStatus, resolution_what.trim(), resolution_how.trim(), ticketId]
    );

    res.json({ message: 'Chamado resolvido e atualizado com sucesso.' });
  } catch (err) {
    res.status(500).json({ error: 'Erro ao resolver chamado.' });
  }
});

// ==========================================
// MÓDULO DE COMUNICAÇÃO (CHAT INTERNO)
// ==========================================

// Listar mensagens do chamado
app.get('/api/tickets/:id/messages', authenticateToken, async (req, res) => {
  const db = await getDB();
  const ticketId = parseInt(req.params.id, 10);

  // Verificação de acesso ao chamado
  const ticket = await db.get('SELECT user_id FROM tickets WHERE id = ?', [ticketId]);
  if (!ticket) {
    return res.status(404).json({ error: 'Chamado não encontrado.' });
  }

  if (req.user.role !== 'ADMIN' && ticket.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Acesso negado às mensagens deste chamado.' });
  }

  const messages = await db.all(
    'SELECT * FROM messages WHERE ticket_id = ? ORDER BY created_at ASC',
    [ticketId]
  );

  res.json(messages);
});

// Enviar mensagem no chamado
app.post('/api/tickets/:id/messages', authenticateToken, async (req, res) => {
  const db = await getDB();
  const ticketId = parseInt(req.params.id, 10);
  const { message } = req.body;

  if (!message || !message.trim()) {
    return res.status(400).json({ error: 'A mensagem não pode ser vazia.' });
  }

  const ticket = await db.get('SELECT user_id FROM tickets WHERE id = ?', [ticketId]);
  if (!ticket) {
    return res.status(404).json({ error: 'Chamado não encontrado.' });
  }

  if (req.user.role !== 'ADMIN' && ticket.user_id !== req.user.id) {
    return res.status(403).json({ error: 'Sem permissão para enviar mensagem neste chamado.' });
  }

  const result = await db.run(
    'INSERT INTO messages (ticket_id, user_id, author_name, message) VALUES (?, ?, ?, ?)',
    [ticketId, req.user.id, req.user.username, message.trim()]
  );

  const newMessage = await db.get('SELECT * FROM messages WHERE id = ?', [result.lastID]);
  res.status(201).json(newMessage);
});

// ==========================================
// FRONTEND INTERFACE - SPA (HTML/CSS/JS)
// ==========================================

app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sistema Helpdesk | Operacional</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .modal-active { overflow: hidden; }
  </style>
</head>
<body class="bg-slate-100 text-slate-800 antialiased min-h-screen flex flex-col">

  <!-- TOPNAV -->
  <header class="bg-slate-900 text-white shadow-lg sticky top-0 z-40">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="bg-indigo-600 p-2 rounded-lg"><i class="fa-solid fa-headset text-xl"></i></div>
        <span class="font-bold text-lg tracking-wide">RS Helpdesk</span>
      </div>
      <div id="user-badge" class="hidden items-center gap-4">
        <span class="text-sm font-medium text-slate-300" id="current-user-display"></span>
        <button id="btn-change-pass" onclick="openChangePassModal()" class="hidden text-xs bg-slate-700 hover:bg-slate-600 px-3 py-1.5 rounded-md transition">
          <i class="fa-solid fa-key mr-1"></i> Alterar Senha
        </button>
        <button onclick="logout()" class="text-xs bg-rose-600 hover:bg-rose-700 px-3 py-1.5 rounded-md font-medium transition">
          <i class="fa-solid fa-right-from-bracket mr-1"></i> Sair
        </button>
      </div>
    </div>
  </header>

  <!-- CONTENT -->
  <main class="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6">
    
    <!-- AUTH SCREEN -->
    <section id="auth-screen" class="max-w-md mx-auto my-12 bg-white p-8 rounded-2xl shadow-xl border border-slate-200">
      <div class="text-center mb-6">
        <h1 class="text-2xl font-bold text-slate-900">Acesso ao Helpdesk</h1>
        <p class="text-sm text-slate-500 mt-1">Entre com seu e-mail ou nome de usuário</p>
      </div>
      <form onsubmit="handleLogin(event)" class="space-y-4">
        <div>
          <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">E-mail ou Username</label>
          <input type="text" id="login-id" required class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
        </div>
        <div>
          <label class="block text-xs font-semibold uppercase text-slate-600 mb-1">Senha</label>
          <input type="password" id="login-pass" required class="w-full px-4 py-2.5 border border-slate-300 rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none">
        </div>
        <button type="submit" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2.5 rounded-lg shadow transition">
          Entrar
        </button>
      </form>
    </section>

    <!-- MAIN DASHBOARD -->
    <section id="dashboard-screen" class="hidden space-y-6">
      
      <!-- ADMIN CONTROLS (TABS) -->
      <div id="admin-navbar" class="hidden flex gap-2 border-b border-slate-200 pb-2">
        <button onclick="switchTab('tickets')" id="tab-btn-tickets" class="px-4 py-2 rounded-lg font-semibold text-sm bg-indigo-600 text-white">Chamados</button>
        <button onclick="switchTab('users')" id="tab-btn-users" class="px-4 py-2 rounded-lg font-semibold text-sm bg-slate-200 text-slate-700 hover:bg-slate-300">Gestão de Usuários</button>
      </div>

      <!-- TAB: CHAMADOS -->
      <div id="tab-tickets" class="space-y-6">
        
        <!-- FORMULARIO NOVO CHAMADO (VISIVEL APENAS USER) -->
        <div id="user-new-ticket-box" class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
          <h2 class="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2">
            <i class="fa-solid fa-circle-plus text-indigo-600"></i> Abrir Novo Chamado Operacional
          </h2>
          <form onsubmit="handleCreateTicket(event)" class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Nome do Operador no Turno</label>
              <input type="text" id="tk-operator" required class="w-full px-3 py-2 border rounded-lg text-sm">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">E-mail de Contato</label>
              <input type="email" id="tk-email" required class="w-full px-3 py-2 border rounded-lg text-sm">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Telefone / WhatsApp</label>
              <input type="text" id="tk-phone" placeholder="(11) 99999-9999" required class="w-full px-3 py-2 border rounded-lg text-sm">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Turno</label>
              <select id="tk-shift" required class="w-full px-3 py-2 border rounded-lg text-sm bg-white">
                <option value="Manhã">Manhã</option>
                <option value="Tarde">Tarde</option>
                <option value="Noite">Noite</option>
              </select>
            </div>
            <div class="md:col-span-2">
              <label class="block text-xs font-semibold text-slate-600 mb-1">Título do Chamado</label>
              <input type="text" id="tk-title" required class="w-full px-3 py-2 border rounded-lg text-sm">
            </div>
            <div class="md:col-span-3">
              <label class="block text-xs font-semibold text-slate-600 mb-1">Descrição do Problema</label>
              <textarea id="tk-desc" rows="3" required class="w-full px-3 py-2 border rounded-lg text-sm"></textarea>
            </div>
            <div class="md:col-span-3 text-right">
              <button type="submit" class="bg-indigo-600 hover:bg-indigo-700 text-white font-semibold px-6 py-2 rounded-lg text-sm transition">
                Enviar Chamado
              </button>
            </div>
          </form>
        </div>

        <!-- LISTA DE CHAMADOS -->
        <div class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div class="p-4 border-b border-slate-200 font-bold text-slate-800 flex justify-between items-center">
            <span>Painel de Chamados</span>
            <button onclick="loadTickets()" class="text-xs text-indigo-600 hover:underline"><i class="fa-solid fa-rotate-right"></i> Atualizar</button>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="bg-slate-50 text-slate-500 uppercase font-bold border-b border-slate-200">
                <tr>
                  <th class="p-3">ID</th>
                  <th class="p-3">Operador / Turno</th>
                  <th class="p-3">Contato</th>
                  <th class="p-3">Título</th>
                  <th class="p-3">Status</th>
                  <th class="p-3 text-center">Ações</th>
                </tr>
              </thead>
              <tbody id="tickets-table-body" class="divide-y divide-slate-100"></tbody>
            </table>
          </div>
        </div>

      </div>

      <!-- TAB: USUÁRIOS (ADMIN ONLY) -->
      <div id="tab-users" class="hidden space-y-6">
        <div class="bg-white p-6 rounded-xl shadow-sm border border-slate-200">
          <h2 class="text-lg font-bold text-slate-800 mb-4">Novo Usuário</h2>
          <form onsubmit="handleCreateUser(event)" class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Username</label>
              <input type="text" id="usr-username" required class="w-full px-3 py-2 border rounded-lg text-sm">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">E-mail</label>
              <input type="email" id="usr-email" required class="w-full px-3 py-2 border rounded-lg text-sm">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Senha Inicial</label>
              <input type="password" id="usr-password" required class="w-full px-3 py-2 border rounded-lg text-sm">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Perfil (RBAC)</label>
              <select id="usr-role" required class="w-full px-3 py-2 border rounded-lg text-sm bg-white">
                <option value="USER">USER</option>
                <option value="ADMIN">ADMIN</option>
              </select>
            </div>
            <div class="md:col-span-4 text-right">
              <button type="submit" class="bg-emerald-600 hover:bg-emerald-700 text-white font-semibold px-6 py-2 rounded-lg text-sm transition">
                Cadastrar Usuário
              </button>
            </div>
          </form>
        </div>

        <div class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
          <div class="p-4 border-b border-slate-200 font-bold text-slate-800">Usuários Cadastrados</div>
          <div class="overflow-x-auto">
            <table class="w-full text-left text-xs border-collapse">
              <thead class="bg-slate-50 text-slate-500 uppercase font-bold border-b border-slate-200">
                <tr>
                  <th class="p-3">ID</th>
                  <th class="p-3">Username</th>
                  <th class="p-3">E-mail</th>
                  <th class="p-3">Perfil</th>
                  <th class="p-3 text-center">Ações</th>
                </tr>
              </thead>
              <tbody id="users-table-body" class="divide-y divide-slate-100"></tbody>
            </table>
          </div>
        </div>
      </div>

    </section>

  </main>

  <!-- MODAL CHAT E DETALHES -->
  <div id="modal-chat" class="hidden fixed inset-0 bg-slate-900/60 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-xl shadow-2xl max-w-2xl w-full max-h-[90vh] flex flex-col overflow-hidden">
      <div class="p-4 bg-slate-800 text-white flex justify-between items-center">
        <h3 class="font-bold text-sm" id="chat-title">Detalhes e Chat do Chamado</h3>
        <button onclick="closeModal('modal-chat')" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="p-4 overflow-y-auto space-y-4 flex-1">
        <div id="chat-ticket-details" class="bg-slate-50 p-3 rounded-lg border border-slate-200 text-xs space-y-1"></div>
        <div id="chat-resolution-details" class="hidden bg-emerald-50 p-3 rounded-lg border border-emerald-200 text-xs text-emerald-900 space-y-1"></div>
        <hr>
        <div class="font-bold text-xs text-slate-700">Histórico de Mensagens</div>
        <div id="chat-messages-list" class="space-y-2 min-h-[150px] max-h-[250px] overflow-y-auto p-2 bg-slate-50 rounded-lg border"></div>
      </div>
      <div class="p-3 bg-slate-100 border-t flex gap-2">
        <input type="text" id="chat-input" placeholder="Digite uma mensagem..." class="flex-1 px-3 py-2 text-xs border rounded-lg outline-none focus:ring-1 focus:ring-indigo-500">
        <button onclick="sendChatMessage()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 text-xs rounded-lg font-semibold">Enviar</button>
      </div>
    </div>
  </div>

  <!-- MODAL RESOLUÇÃO TÉCNICA (ADMIN ONLY) -->
  <div id="modal-resolve" class="hidden fixed inset-0 bg-slate-900/60 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-xl shadow-2xl max-w-md w-full p-6 space-y-4">
      <h3 class="font-bold text-slate-900 border-b pb-2">Resolução Técnica de Chamado</h3>
      <input type="hidden" id="resolve-ticket-id">
      <div>
        <label class="block text-xs font-semibold text-slate-600 mb-1">Status Final</label>
        <select id="resolve-status" class="w-full px-3 py-2 border rounded-lg text-sm bg-white">
          <option value="Concluído">Concluído</option>
          <option value="Em Andamento">Em Andamento</option>
          <option value="Cancelado">Cancelado</option>
        </select>
      </div>
      <div>
        <label class="block text-xs font-semibold text-slate-600 mb-1">O que foi feito?</label>
        <textarea id="resolve-what" rows="3" required class="w-full px-3 py-2 border rounded-lg text-xs"></textarea>
      </div>
      <div>
        <label class="block text-xs font-semibold text-slate-600 mb-1">Como foi realizado?</label>
        <textarea id="resolve-how" rows="3" required class="w-full px-3 py-2 border rounded-lg text-xs"></textarea>
      </div>
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="closeModal('modal-resolve')" class="px-4 py-2 bg-slate-200 text-slate-700 text-xs rounded-lg font-semibold">Cancelar</button>
        <button onclick="submitResolution()" class="px-4 py-2 bg-emerald-600 text-white text-xs rounded-lg font-semibold hover:bg-emerald-700">Salvar Resolução</button>
      </div>
    </div>
  </div>

  <!-- MODAL REDEFINIR SENHA POR ADMIN -->
  <div id="modal-admin-pass" class="hidden fixed inset-0 bg-slate-900/60 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-xl shadow-2xl max-w-sm w-full p-6 space-y-4">
      <h3 class="font-bold text-slate-900 border-b pb-2">Redefinir Senha de Usuário</h3>
      <input type="hidden" id="admin-pass-target-id">
      <div>
        <label class="block text-xs font-semibold text-slate-600 mb-1">Nova Senha</label>
        <input type="password" id="admin-pass-input" required class="w-full px-3 py-2 border rounded-lg text-sm">
      </div>
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="closeModal('modal-admin-pass')" class="px-4 py-2 bg-slate-200 text-slate-700 text-xs rounded-lg font-semibold">Cancelar</button>
        <button onclick="submitAdminPasswordChange()" class="px-4 py-2 bg-indigo-600 text-white text-xs rounded-lg font-semibold hover:bg-indigo-700">Atualizar Senha</button>
      </div>
    </div>
  </div>

  <!-- MODAL ALTERAR PRÓPRIA SENHA -->
  <div id="modal-change-pass" class="hidden fixed inset-0 bg-slate-900/60 z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-xl shadow-2xl max-w-sm w-full p-6 space-y-4">
      <h3 class="font-bold text-slate-900 border-b pb-2">Alterar Minha Senha</h3>
      <div>
        <label class="block text-xs font-semibold text-slate-600 mb-1">Nova Senha</label>
        <input type="password" id="self-pass-input" required class="w-full px-3 py-2 border rounded-lg text-sm">
      </div>
      <div class="flex justify-end gap-2 pt-2">
        <button onclick="closeModal('modal-change-pass')" class="px-4 py-2 bg-slate-200 text-slate-700 text-xs rounded-lg font-semibold">Cancelar</button>
        <button onclick="submitSelfPasswordChange()" class="px-4 py-2 bg-indigo-600 text-white text-xs rounded-lg font-semibold hover:bg-indigo-700">Salvar Nova Senha</button>
      </div>
    </div>
  </div>

  <script>
    let token = localStorage.getItem('token');
    let currentUser = JSON.parse(localStorage.getItem('user') || 'null');
    let currentActiveChatTicketId = null;

    function init() {
      if (token && currentUser) {
        document.getElementById('auth-screen').classList.add('hidden');
        document.getElementById('dashboard-screen').classList.remove('hidden');
        document.getElementById('user-badge').classList.remove('hidden');
        document.getElementById('user-badge').classList.add('flex');
        document.getElementById('current-user-display').innerText = \`\${currentUser.username} (\${currentUser.role})\`;

        // Ocultar totalmente recursos e botões de alteração de senha se perfil for USER
        if (currentUser.role === 'ADMIN') {
          document.getElementById('admin-navbar').classList.remove('hidden');
          document.getElementById('btn-change-pass').classList.remove('hidden');
          document.getElementById('user-new-ticket-box').classList.add('hidden');
          loadUsers();
        } else {
          document.getElementById('btn-change-pass').classList.add('hidden');
          document.getElementById('user-new-ticket-box').classList.remove('hidden');
        }

        loadTickets();
      } else {
        document.getElementById('auth-screen').classList.remove('hidden');
        document.getElementById('dashboard-screen').classList.add('hidden');
        document.getElementById('user-badge').classList.add('hidden');
      }
    }

    async function apiFetch(url, options = {}) {
      options.headers = options.headers || {};
      options.headers['Content-Type'] = 'application/json';
      if (token) options.headers['Authorization'] = 'Bearer ' + token;

      const res = await fetch(url, options);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Erro na requisição');
      return data;
    }

    async function handleLogin(e) {
      e.preventDefault();
      try {
        const loginIdentifier = document.getElementById('login-id').value;
        const password = document.getElementById('login-pass').value;
        const data = await apiFetch('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({ loginIdentifier, password })
        });

        token = data.token;
        currentUser = data.user;
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(currentUser));
        init();
      } catch (err) {
        alert(err.message);
      }
    }

    function logout() {
      localStorage.clear();
      token = null;
      currentUser = null;
      init();
    }

    function switchTab(tab) {
      if (tab === 'tickets') {
        document.getElementById('tab-tickets').classList.remove('hidden');
        document.getElementById('tab-users').classList.add('hidden');
        document.getElementById('tab-btn-tickets').className = 'px-4 py-2 rounded-lg font-semibold text-sm bg-indigo-600 text-white';
        document.getElementById('tab-btn-users').className = 'px-4 py-2 rounded-lg font-semibold text-sm bg-slate-200 text-slate-700 hover:bg-slate-300';
      } else {
        document.getElementById('tab-tickets').classList.add('hidden');
        document.getElementById('tab-users').classList.remove('hidden');
        document.getElementById('tab-btn-users').className = 'px-4 py-2 rounded-lg font-semibold text-sm bg-indigo-600 text-white';
        document.getElementById('tab-btn-tickets').className = 'px-4 py-2 rounded-lg font-semibold text-sm bg-slate-200 text-slate-700 hover:bg-slate-300';
      }
    }

    async function handleCreateTicket(e) {
      e.preventDefault();
      try {
        const payload = {
          operator_name: document.getElementById('tk-operator').value,
          contact_email: document.getElementById('tk-email').value,
          contact_phone: document.getElementById('tk-phone').value,
          shift: document.getElementById('tk-shift').value,
          title: document.getElementById('tk-title').value,
          description: document.getElementById('tk-desc').value
        };

        await apiFetch('/api/tickets', { method: 'POST', body: JSON.stringify(payload) });
        alert('Chamado aberto com sucesso!');
        e.target.reset();
        loadTickets();
      } catch (err) {
        alert(err.message);
      }
    }

    async function loadTickets() {
      try {
        const tickets = await apiFetch('/api/tickets');
        const tbody = document.getElementById('tickets-table-body');
        tbody.innerHTML = '';

        tickets.forEach(t => {
          const tr = document.createElement('tr');
          tr.className = 'hover:bg-slate-50 border-b border-slate-100';
          
          let actionButtons = \`<button onclick="openChatModal(\${t.id})" class="bg-indigo-50 text-indigo-600 hover:bg-indigo-100 px-2.5 py-1 rounded font-semibold text-xs transition"><i class="fa-solid fa-comments"></i> Chat/Ver</button>\`;
          
          if (currentUser.role === 'ADMIN') {
            actionButtons += \` <button onclick="openResolveModal(\${t.id})" class="bg-emerald-50 text-emerald-600 hover:bg-emerald-100 px-2.5 py-1 rounded font-semibold text-xs transition ml-1"><i class="fa-solid fa-check"></i> Resolver</button>\`;
          }

          let badgeColor = 'bg-amber-100 text-amber-800';
          if (t.status === 'Concluído') badgeColor = 'bg-emerald-100 text-emerald-800';
          if (t.status === 'Em Andamento') badgeColor = 'bg-blue-100 text-blue-800';
          if (t.status === 'Cancelado') badgeColor = 'bg-rose-100 text-rose-800';

          tr.innerHTML = \`
            <td class="p-3 font-bold text-slate-700">#\${t.id}</td>
            <td class="p-3"><div>\${t.operator_name}</div><div class="text-[10px] text-slate-400">\${t.shift}</div></td>
            <td class="p-3"><div>\${t.contact_email}</div><div class="text-[10px] text-slate-400">\${t.contact_phone}</div></td>
            <td class="p-3 font-medium">\${t.title}</td>
            <td class="p-3"><span class="px-2 py-0.5 rounded-full text-[10px] font-bold \${badgeColor}">\${t.status}</span></td>
            <td class="p-3 text-center">\${actionButtons}</td>
          \`;
          tbody.appendChild(tr);
        });
      } catch (err) {
        alert('Erro ao carregar chamados: ' + err.message);
      }
    }

    async function loadUsers() {
      try {
        const users = await apiFetch('/api/users');
        const tbody = document.getElementById('users-table-body');
        tbody.innerHTML = '';

        users.forEach(u => {
          const tr = document.createElement('tr');
          tr.className = 'hover:bg-slate-50 border-b border-slate-100';
          
          tr.innerHTML = \`
            <td class="p-3 font-bold">#\${u.id}</td>
            <td class="p-3 font-medium">\${u.username}</td>
            <td class="p-3">\${u.email}</td>
            <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold \${u.role === 'ADMIN' ? 'bg-purple-100 text-purple-800' : 'bg-slate-100 text-slate-700'}">\${u.role}</span></td>
            <td class="p-3 text-center space-x-1">
              <button onclick="openAdminPassModal(\${u.id})" class="bg-amber-50 text-amber-600 hover:bg-amber-100 px-2 py-1 rounded text-xs"><i class="fa-solid fa-key"></i> Pass</button>
              \${u.id !== currentUser.id ? \`<button onclick="deleteUser(\${u.id})" class="bg-rose-50 text-rose-600 hover:bg-rose-100 px-2 py-1 rounded text-xs"><i class="fa-solid fa-trash"></i></button>\` : ''}
            </td>
          \`;
          tbody.appendChild(tr);
        });
      } catch (err) {
        alert('Erro ao carregar usuários: ' + err.message);
      }
    }

    async function handleCreateUser(e) {
      e.preventDefault();
      try {
        const payload = {
          username: document.getElementById('usr-username').value,
          email: document.getElementById('usr-email').value,
          password: document.getElementById('usr-password').value,
          role: document.getElementById('usr-role').value
        };

        await apiFetch('/api/users', { method: 'POST', body: JSON.stringify(payload) });
        alert('Usuário cadastrado!');
        e.target.reset();
        loadUsers();
      } catch (err) {
        alert(err.message);
      }
    }

    async function deleteUser(id) {
      if (!confirm('Deseja realmente excluir este usuário?')) return;
      try {
        await apiFetch('/api/users/' + id, { method: 'DELETE' });
        loadUsers();
      } catch (err) {
        alert(err.message);
      }
    }

    async function openChatModal(ticketId) {
      currentActiveChatTicketId = ticketId;
      document.getElementById('chat-title').innerText = 'Chamado #' + ticketId;
      document.getElementById('modal-chat').classList.remove('hidden');

      const tickets = await apiFetch('/api/tickets');
      const ticket = tickets.find(t => t.id === ticketId);

      if (ticket) {
        document.getElementById('chat-ticket-details').innerHTML = \`
          <div><strong>Operador:</strong> \${ticket.operator_name} (\${ticket.shift})</div>
          <div><strong>Contato:</strong> \${ticket.contact_email} | \${ticket.contact_phone}</div>
          <div><strong>Assunto:</strong> \${ticket.title}</div>
          <div><strong>Descrição:</strong> \${ticket.description}</div>
        \`;

        const resBox = document.getElementById('chat-resolution-details');
        if (ticket.resolution_what && ticket.resolution_how) {
          resBox.classList.remove('hidden');
          resBox.innerHTML = \`
            <div class="font-bold text-xs border-b border-emerald-200 pb-1 mb-1">Resolução Técnica (\${ticket.status})</div>
            <div><strong>O que foi feito:</strong> \${ticket.resolution_what}</div>
            <div><strong>Como foi feito:</strong> \${ticket.resolution_how}</div>
          \`;
        } else {
          resBox.classList.add('hidden');
        }
      }

      await loadChatMessages();
    }

    async function loadChatMessages() {
      if (!currentActiveChatTicketId) return;
      try {
        const msgs = await apiFetch('/api/tickets/' + currentActiveChatTicketId + '/messages');
        const list = document.getElementById('chat-messages-list');
        list.innerHTML = '';

        msgs.forEach(m => {
          const div = document.createElement('div');
          div.className = 'p-2 rounded-lg text-xs bg-white border border-slate-200';
          div.innerHTML = \`
            <div class="flex justify-between text-[10px] text-slate-400 mb-1">
              <span class="font-bold text-slate-700">\${m.author_name}</span>
              <span>\${new Date(m.created_at).toLocaleString('pt-BR')}</span>
            </div>
            <div class="text-slate-800">\${m.message}</div>
          \`;
          list.appendChild(div);
        });
        list.scrollTop = list.scrollHeight;
      } catch (err) {
        alert(err.message);
      }
    }

    async function sendChatMessage() {
      const input = document.getElementById('chat-input');
      const message = input.value;
      if (!message || !currentActiveChatTicketId) return;

      try {
        await apiFetch('/api/tickets/' + currentActiveChatTicketId + '/messages', {
          method: 'POST',
          body: JSON.stringify({ message })
        });
        input.value = '';
        loadChatMessages();
      } catch (err) {
        alert(err.message);
      }
    }

    function openResolveModal(ticketId) {
      document.getElementById('resolve-ticket-id').value = ticketId;
      document.getElementById('modal-resolve').classList.remove('hidden');
    }

    async function submitResolution() {
      const ticketId = document.getElementById('resolve-ticket-id').value;
      const status = document.getElementById('resolve-status').value;
      const resolution_what = document.getElementById('resolve-what').value;
      const resolution_how = document.getElementById('resolve-how').value;

      try {
        await apiFetch('/api/tickets/' + ticketId + '/resolve', {
          method: 'PUT',
          body: JSON.stringify({ status, resolution_what, resolution_how })
        });
        alert('Chamado atualizado com sucesso!');
        closeModal('modal-resolve');
        loadTickets();
      } catch (err) {
        alert(err.message);
      }
    }

    function openAdminPassModal(userId) {
      document.getElementById('admin-pass-target-id').value = userId;
      document.getElementById('modal-admin-pass').classList.remove('hidden');
    }

    async function submitAdminPasswordChange() {
      const userId = document.getElementById('admin-pass-target-id').value;
      const newPassword = document.getElementById('admin-pass-input').value;

      try {
        await apiFetch('/api/users/' + userId + '/password', {
          method: 'PUT',
          body: JSON.stringify({ newPassword })
        });
        alert('Senha redefinida com sucesso!');
        closeModal('modal-admin-pass');
      } catch (err) {
        alert(err.message);
      }
    }

    function openChangePassModal() {
      document.getElementById('modal-change-pass').classList.remove('hidden');
    }

    async function submitSelfPasswordChange() {
      const newPassword = document.getElementById('self-pass-input').value;

      try {
        await apiFetch('/api/users/' + currentUser.id + '/password', {
          method: 'PUT',
          body: JSON.stringify({ newPassword })
        });
        alert('Sua senha foi alterada com sucesso!');
        closeModal('modal-change-pass');
      } catch (err) {
        alert(err.message);
      }
    }

    function closeModal(id) {
      document.getElementById(id).classList.add('hidden');
    }

    window.onload = init;
  </script>
</body>
</html>
  `);
});

// Inicialização do Servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await getDB();
  console.log(`Servidor de Helpdesk rodando na porta ${PORT}`);
});