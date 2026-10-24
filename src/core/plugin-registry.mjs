/**
 * AegisWin Compile-Time Plugin Registry & Per-Tool Gate Policy Engine
 * - Manages self-contained plugins and their discrete tools
 * - Tracks First-Run Setup Wizard component selections
 * - Resolves effective gate policy ('auto' | 'pin_required') per tool
 */

export class PluginRegistry {
  constructor(vault, llmService) {
    this.vault = vault;
    this.llmService = llmService;
    this.plugins = new Map();
  }

  registerPlugin(pluginDefinition) {
    const { manifest, handlers } = pluginDefinition;
    if (!manifest?.id || !manifest?.name || !Array.isArray(manifest?.tools)) {
      throw new Error('Invalid plugin manifest: missing id, name, or tools array.');
    }
    for (const tool of manifest.tools) {
      if (!tool.id || !['auto', 'pin_required'].includes(tool.defaultGatePolicy)) {
        throw new Error(`Invalid tool "${tool.id}" in plugin "${manifest.id}": must specify defaultGatePolicy ('auto' | 'pin_required').`);
      }
      if (typeof handlers?.[tool.id] !== 'function') {
        throw new Error(`Missing handler function for tool "${manifest.id}:${tool.id}".`);
      }
    }
    this.plugins.set(manifest.id, pluginDefinition);
  }

  completeFirstRunSetup({ selectedPlugins, selectedComponents }) {
    this.vault.updateState((s) => {
      s.firstRunCompleted = true;
      if (Array.isArray(selectedPlugins)) {
        s.installedPlugins = selectedPlugins;
      }
      if (selectedComponents && typeof selectedComponents === 'object') {
        s.installedComponents = { ...s.installedComponents, ...selectedComponents };
      }
      return s;
    });
    return this.vault.getState();
  }

  isPluginInstalled(pluginId) {
    const state = this.vault.getState();
    return (state.installedPlugins || []).includes(pluginId);
  }

  getToolGatePolicy(pluginId, toolId) {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) throw new Error(`Unknown plugin: ${pluginId}`);
    const tool = plugin.manifest.tools.find((t) => t.id === toolId);
    if (!tool) throw new Error(`Unknown tool: ${pluginId}:${toolId}`);

    const state = this.vault.getState();
    const key = `${pluginId}:${toolId}`;
    return state.toolGateOverrides?.[key] || tool.defaultGatePolicy;
  }

  setToolGatePolicy(pluginId, toolId, policy) {
    if (!['auto', 'pin_required'].includes(policy)) {
      throw new Error(`Invalid gate policy: ${policy}`);
    }
    this.getToolGatePolicy(pluginId, toolId);
    const key = `${pluginId}:${toolId}`;
    this.vault.updateState((s) => {
      s.toolGateOverrides = { ...(s.toolGateOverrides || {}), [key]: policy };
      return s;
    });
    return policy;
  }

  listAvailablePlugins() {
    const state = this.vault.getState();
    return Array.from(this.plugins.values()).map(({ manifest }) => ({
      ...manifest,
      installed: (state.installedPlugins || []).includes(manifest.id),
      externalLlmTrusted: (state.trustedExternalLlmPlugins || []).includes(manifest.id),
      tools: manifest.tools.map((t) => ({
        ...t,
        qualifiedName: `${manifest.id}:${t.id}`,
        effectiveGatePolicy: this.getToolGatePolicy(manifest.id, t.id),
      })),
    }));
  }

  listMcpTools() {
    const tools = [];
    for (const plugin of this.listAvailablePlugins()) {
      if (!plugin.installed) continue;
      for (const tool of plugin.tools) {
        tools.push({
          name: `${plugin.id}:${tool.id}`,
          pluginId: plugin.id,
          toolId: tool.id,
          description: `[${plugin.name}] ${tool.description}`,
          requiresAdmin: !!tool.requiresAdmin,
          gatePolicy: tool.effectiveGatePolicy,
          inputSchema: tool.inputSchema || { type: 'object', properties: {} },
        });
      }
    }
    return tools;
  }

  async executeToolDirect(pluginId, toolId, args = {}, context = {}) {
    if (!this.isPluginInstalled(pluginId)) {
      throw new Error(`Plugin "${pluginId}" is not currently enabled/installed.`);
    }
    const plugin = this.plugins.get(pluginId);
    if (!plugin) throw new Error(`Plugin "${pluginId}" not found.`);
    const tool = plugin.manifest.tools.find((t) => t.id === toolId);
    if (!tool) throw new Error(`Tool "${pluginId}:${toolId}" not found.`);

    const handler = plugin.handlers[toolId];
    return await handler(args, {
      vault: this.vault,
      llmService: this.llmService,
      installedComponents: this.vault.getState().installedComponents || {},
      isElevatedAdmin: !!context.isElevatedAdmin,
      ...context,
    });
  }
}
