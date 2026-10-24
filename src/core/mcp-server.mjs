/**
 * AegisWin Local MCP HTTP Server & Out-of-Band PIN Approval Web Portal
 * - Serves JSON-RPC / REST MCP endpoints at POST /mcp with Bearer key authorization
 * - Automatically opens/closes the configured TCP port in Windows Firewall when started/stopped
 * - Intercepts calls to 'pin_required' tools, creating a pending ticket and returning
 *   the approval page URL: http://<host>:<port>/approve/<ticket-id>
 * - Serves a high-contrast dark HTML approval page with Accept, Decline, Comments, and PIN field
 * - Verifies PIN strictly in local memory via PortableVault (AI never sees the PIN)
 */
import http from 'node:http';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';

export class FirewallPortManager {
  constructor(executor = null) {
    this.executor = executor || this._defaultExecutor.bind(this);
    this.activeRules = new Set();
  }

  openPort(port, rulePrefix = 'AegisWin_MCP') {
    const ruleName = `${rulePrefix}_${port}`;
    const cmd = `netsh advfirewall firewall add rule name="${ruleName}" dir=in action=allow protocol=TCP localport=${port} profile=private`;
    const result = this.executor(cmd);
    this.activeRules.add({ port, ruleName, cmd });
    return { opened: true, port, ruleName, command: cmd, output: result };
  }

  closePort(port, rulePrefix = 'AegisWin_MCP') {
    const ruleName = `${rulePrefix}_${port}`;
    const cmd = `netsh advfirewall firewall delete rule name="${ruleName}" protocol=TCP localport=${port}`;
    const result = this.executor(cmd);
    for (const item of this.activeRules) {
      if (item.port === port) this.activeRules.delete(item);
    }
    return { closed: true, port, ruleName, command: cmd, output: result };
  }

  _defaultExecutor(cmd) {
    if (process.platform === 'win32') {
      try {
        return execSync(cmd, { stdio: 'pipe', encoding: 'utf8' });
      } catch (err) {
        return `Requires elevation or simulated: ${err.message}`;
      }
    }
    return `[Simulated on ${process.platform}] ${cmd}`;
  }
}

export class LocalMcpServer {
  constructor({ vault, registry, firewallManager = new FirewallPortManager() }) {
    this.vault = vault;
    this.registry = registry;
    this.firewallManager = firewallManager;
    this.tickets = new Map();
    this.server = null;
    this.boundPort = null;
    this.firewallStatus = null;
  }

  async start(overridePort = null) {
    if (this.server) return this.getStatus();

    const state = this.vault.getState();
    const host = state.mcpConfig.host || '127.0.0.1';
    const requestedPort = overridePort !== null ? overridePort : state.mcpConfig.port || 47821;

    this.server = http.createServer((req, res) => this._handleRequest(req, res));

    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(requestedPort, host, () => {
        this.boundPort = this.server.address().port;
        resolve();
      });
    });

    if (state.mcpConfig.autoOpenFirewall) {
      this.firewallStatus = this.firewallManager.openPort(this.boundPort);
    }

    return this.getStatus();
  }

  async stop() {
    if (!this.server) return { running: false };
    const portToClose = this.boundPort;
    await new Promise((resolve) => this.server.close(() => resolve()));
    this.server = null;
    this.boundPort = null;

    let closeFirewallResult = null;
    if (portToClose && this.vault.getState().mcpConfig.autoOpenFirewall) {
      closeFirewallResult = this.firewallManager.closePort(portToClose);
    }
    return { running: false, firewallCleanedUp: closeFirewallResult };
  }

  getStatus() {
    const state = this.vault.getState();
    return {
      running: !!this.server,
      host: state.mcpConfig.host || '127.0.0.1',
      port: this.boundPort,
      firewallStatus: this.firewallStatus,
      pendingTicketsCount: Array.from(this.tickets.values()).filter((t) => t.status === 'pending_approval').length,
    };
  }

  listTickets() {
    return Array.from(this.tickets.values()).map((t) => this._sanitizeTicketForExternal(t));
  }

  _sanitizeTicketForExternal(ticket) {
    return {
      ticketId: ticket.ticketId,
      pluginId: ticket.pluginId,
      toolId: ticket.toolId,
      qualifiedName: `${ticket.pluginId}:${ticket.toolId}`,
      args: ticket.args,
      status: ticket.status,
      approvalUrl: ticket.approvalUrl,
      userComment: this.vault.scrubForExternalOutput(ticket.userComment || ''),
      createdAt: ticket.createdAt,
      decidedAt: ticket.decidedAt || null,
      result: ticket.result
        ? JSON.parse(this.vault.scrubForExternalOutput(JSON.stringify(ticket.result)))
        : null,
      error: ticket.error || null,
    };
  }

  async _handleRequest(req, res) {
    try {
      const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);

      if (url.pathname.startsWith('/approve/')) {
        const ticketId = decodeURIComponent(url.pathname.replace('/approve/', '').trim());
        if (req.method === 'GET') {
          return this._serveApprovalPage(ticketId, res);
        }
        if (req.method === 'POST') {
          return await this._handleApprovalSubmission(ticketId, req, res);
        }
      }

      if (url.pathname === '/mcp' && req.method === 'POST') {
        const expectedKey = this.vault.getState().mcpConfig.authKey;
        const authHeader = req.headers['authorization'] || '';
        const providedKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

        if (!expectedKey || providedKey !== expectedKey) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'UNAUTHORIZED: Valid MCP Bearer key required.' }));
          return;
        }

        const body = await this._readJsonBody(req);
        return await this._handleMcpRpc(body, res);
      }

      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not Found' }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: this.vault.scrubForExternalOutput(err.message) }));
    }
  }

  async _handleMcpRpc(body, res) {
    const { method, params = {}, id = 1 } = body;

    if (method === 'tools/list') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            tools: [
              ...this.registry.listMcpTools(),
              {
                name: 'mcp:check_ticket',
                description: 'Checks the approval status, user comments, and execution result of a pending approval ticket.',
                gatePolicy: 'auto',
                inputSchema: {
                  type: 'object',
                  required: ['ticketId'],
                  properties: { ticketId: { type: 'string' } },
                },
              },
            ],
          },
        })
      );
      return;
    }

    if (method === 'tools/call') {
      const toolName = params.name || '';
      const toolArgs = params.arguments || {};

      if (toolName === 'mcp:check_ticket') {
        const ticket = this.tickets.get(toolArgs.ticketId);
        if (!ticket) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { message: 'Ticket not found' } }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: this._sanitizeTicketForExternal(ticket),
          })
        );
        return;
      }

      const [pluginId, toolId] = toolName.split(':');
      const policy = this.registry.getToolGatePolicy(pluginId, toolId);

      if (policy === 'auto') {
        const execResult = await this.registry.executeToolDirect(pluginId, toolId, toolArgs);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              status: 'completed',
              tool: toolName,
              output: JSON.parse(this.vault.scrubForExternalOutput(JSON.stringify(execResult))),
            },
          })
        );
        return;
      }

      const ticketId = `T-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
      const host = this.vault.getState().mcpConfig.host || '127.0.0.1';
      const approvalUrl = `http://${host}:${this.boundPort}/approve/${ticketId}`;

      const ticket = {
        ticketId,
        pluginId,
        toolId,
        args: toolArgs,
        status: 'pending_approval',
        approvalUrl,
        userComment: '',
        createdAt: new Date().toISOString(),
        decidedAt: null,
        result: null,
      };
      this.tickets.set(ticketId, ticket);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            status: 'pending_approval',
            ticketId,
            approvalUrl,
            message: `Action "${toolName}" requires human approval. Present this URL to the user: ${approvalUrl}`,
          },
        })
      );
      return;
    }

    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { message: `Unsupported MCP method: ${method}` } }));
  }

  _serveApprovalPage(ticketId, res) {
    const ticket = this.tickets.get(ticketId);
    if (!ticket) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<h1>404 - Approval Ticket Not Found</h1>');
      return;
    }

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AegisWin Action Approval — ${ticket.ticketId}</title>
  <style>
    :root {
      --bg: #090D16;
      --card: #111827;
      --border: #374151;
      --text: #F9FAFB;
      --accent: #38BDF8;
    }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: system-ui, -apple-system, Segoe UI, sans-serif;
      margin: 0;
      padding: 2rem;
      display: flex;
      justify-content: center;
    }
    .card {
      background: var(--card);
      border: 2px solid var(--border);
      border-radius: 12px;
      max-width: 580px;
      width: 100%;
      padding: 1.75rem;
    }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.6rem;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.8rem;
      background: #1E293B;
      color: var(--accent);
      border: 1px solid var(--accent);
    }
    pre {
      background: #030712;
      border: 1px solid var(--border);
      padding: 0.85rem;
      border-radius: 8px;
      overflow-x: auto;
      color: #E5E7EB;
    }
    label {
      display: block;
      font-weight: 600;
      margin-top: 1rem;
      margin-bottom: 0.4rem;
    }
    textarea, input[type="password"] {
      width: 100%;
      box-sizing: border-box;
      background: #030712;
      border: 2px solid var(--border);
      color: var(--text);
      padding: 0.65rem;
      border-radius: 8px;
      font-size: 1rem;
    }
    .decision-group {
      display: flex;
      gap: 1rem;
      margin-top: 0.5rem;
    }
    .decision-option {
      flex: 1;
      border: 2px solid var(--border);
      border-radius: 8px;
      padding: 0.75rem;
      text-align: center;
      cursor: pointer;
      font-weight: 700;
    }
    button[type="submit"] {
      margin-top: 1.25rem;
      width: 100%;
      padding: 0.85rem;
      background: var(--accent);
      color: #030712;
      font-weight: 800;
      font-size: 1rem;
      border: none;
      border-radius: 8px;
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">MCP GATED ACTION TICKET ${ticket.ticketId}</span>
    <h2>Approve or Decline Requested Tool Execution</h2>
    <p><strong>Plugin:</strong> ${ticket.pluginId}</p>
    <p><strong>Tool:</strong> ${ticket.toolId}</p>
    <p><strong>Status:</strong> ${ticket.status}</p>
    <label>Requested Arguments:</label>
    <pre>${JSON.stringify(ticket.args, null, 2)}</pre>
    <form method="POST" action="/approve/${ticket.ticketId}">
      <label>Decision:</label>
      <div class="decision-group">
        <label class="decision-option"><input type="radio" name="decision" value="accept" checked /> Accept & Execute</label>
        <label class="decision-option"><input type="radio" name="decision" value="decline" /> Decline Action</label>
      </div>
      <label for="comment">Operator Comments (Returned to AI Agent):</label>
      <textarea id="comment" name="comment" rows="3" placeholder="Optional instructions or reason for decision..."></textarea>
      <label for="pin">Application Security PIN (Never shared with AI):</label>
      <input id="pin" name="pin" type="password" required autocomplete="off" placeholder="Enter startup PIN" />
      <button type="submit">Submit Verified Decision</button>
    </form>
  </div>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }

  async _handleApprovalSubmission(ticketId, req, res) {
    const ticket = this.tickets.get(ticketId);
    if (!ticket) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Ticket not found' }));
      return;
    }
    if (ticket.status !== 'pending_approval') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Ticket already finalized with status: ${ticket.status}` }));
      return;
    }

    const body = await this._readFormOrJsonBody(req);
    const { decision, comment = '', pin = '' } = body;

    if (!this.vault.verifyPin(String(pin))) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'INVALID_PIN: Approval denied due to invalid security PIN.' }));
      return;
    }

    ticket.userComment = this.vault.scrubForExternalOutput(String(comment));
    ticket.decidedAt = new Date().toISOString();

    if (decision === 'accept') {
      ticket.status = 'approved';
      try {
        ticket.result = await this.registry.executeToolDirect(ticket.pluginId, ticket.toolId, ticket.args, {
          approvedByTicket: ticket.ticketId,
        });
      } catch (execErr) {
        ticket.status = 'execution_failed';
        ticket.error = this.vault.scrubForExternalOutput(execErr.message);
      }
    } else {
      ticket.status = 'declined';
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        ok: true,
        ticket: this._sanitizeTicketForExternal(ticket),
      })
    );
  }

  _readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => {
        try {
          resolve(data ? JSON.parse(data) : {});
        } catch (err) {
          reject(err);
        }
      });
      req.on('error', reject);
    });
  }

  _readFormOrJsonBody(req) {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (chunk) => (data += chunk));
      req.on('end', () => {
        try {
          const ct = (req.headers['content-type'] || '').toLowerCase();
          if (ct.includes('application/json')) {
            resolve(data ? JSON.parse(data) : {});
          } else {
            const params = new URLSearchParams(data);
            resolve(Object.fromEntries(params.entries()));
          }
        } catch (err) {
          reject(err);
        }
      });
      req.on('error', reject);
    });
  }
}
