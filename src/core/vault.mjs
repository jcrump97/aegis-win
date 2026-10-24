/**
 * AegisWin Portable Zero-Knowledge Vault (./data/vault.enc.json)
 * - Uses Node native crypto (scrypt KDF + AES-256-GCM authenticated encryption)
 * - Zero external dependencies, portable across any Windows host folder
 * - Enforces the strict invariant: The AI / MCP layer never sees the plaintext PIN.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export class PortableVault {
  constructor(dataDir = path.join(process.cwd(), 'data')) {
    this.dataDir = dataDir;
    this.vaultPath = path.join(this.dataDir, 'vault.enc.json');
    this._derivedKey = null;
    this._pinVerifierHash = null;
    this._salt = null;
    this._activePinShadow = null; // Used strictly in-memory for outbound redaction guard
    this._state = {
      firstRunCompleted: false,
      installedPlugins: ['event-logs', 'windows-health', 'usage-monitor'],
      installedComponents: {
        'usage-monitor:resource-spikes': true,
        'usage-monitor:crash-correlator': true,
        'usage-monitor:active-window': true,
      },
      trustedExternalLlmPlugins: [],
      toolGateOverrides: {},
      uiScale: 1.0,
      llmConfig: {
        baseUrl: 'http://127.0.0.1:11434/v1',
        model: 'llama3.2:latest',
        apiKey: '',
      },
      mcpConfig: {
        enabled: false,
        host: '127.0.0.1',
        port: 47821,
        authKey: crypto.randomBytes(24).toString('hex'),
        autoOpenFirewall: true,
      },
    };
  }

  isInitialized() {
    return fs.existsSync(this.vaultPath);
  }

  isUnlocked() {
    return this._derivedKey !== null;
  }

  unlockWithPin(pin) {
    if (typeof pin !== 'string' || pin.trim().length < 4) {
      throw new Error('PIN must be at least 4 characters.');
    }
    fs.mkdirSync(this.dataDir, { recursive: true });

    if (!this.isInitialized()) {
      this._salt = crypto.randomBytes(16);
      const keyMaterial = crypto.scryptSync(pin, this._salt, 64);
      this._derivedKey = keyMaterial.subarray(0, 32);
      this._pinVerifierHash = keyMaterial.subarray(32, 64);
      this._activePinShadow = pin;
      this.save();
      return { initializedNew: true };
    }

    const raw = JSON.parse(fs.readFileSync(this.vaultPath, 'utf8'));
    const salt = Buffer.from(raw.salt, 'hex');
    const storedVerifier = Buffer.from(raw.verifier, 'hex');
    const keyMaterial = crypto.scryptSync(pin, salt, 64);
    const candidateKey = keyMaterial.subarray(0, 32);
    const candidateVerifier = keyMaterial.subarray(32, 64);

    if (
      storedVerifier.length !== candidateVerifier.length ||
      !crypto.timingSafeEqual(storedVerifier, candidateVerifier)
    ) {
      throw new Error('INVALID_PIN: Startup PIN verification failed.');
    }

    this._salt = salt;
    this._derivedKey = candidateKey;
    this._pinVerifierHash = candidateVerifier;
    this._activePinShadow = pin;
    this._state = this._decryptPayload(raw.ciphertext, raw.iv, raw.authTag);
    return { initializedNew: false };
  }

  verifyPin(candidatePin) {
    if (!this.isUnlocked() || typeof candidatePin !== 'string') {
      return false;
    }
    const keyMaterial = crypto.scryptSync(candidatePin, this._salt, 64);
    const candidateVerifier = keyMaterial.subarray(32, 64);
    return (
      this._pinVerifierHash.length === candidateVerifier.length &&
      crypto.timingSafeEqual(this._pinVerifierHash, candidateVerifier)
    );
  }

  updatePin(currentPin, newPin) {
    if (!this.verifyPin(currentPin)) {
      throw new Error('INVALID_PIN: Current PIN is incorrect.');
    }
    if (typeof newPin !== 'string' || newPin.trim().length < 4) {
      throw new Error('New PIN must be at least 4 characters.');
    }
    this._salt = crypto.randomBytes(16);
    const keyMaterial = crypto.scryptSync(newPin, this._salt, 64);
    this._derivedKey = keyMaterial.subarray(0, 32);
    this._pinVerifierHash = keyMaterial.subarray(32, 64);
    this._activePinShadow = newPin;
    this.save();
    return true;
  }

  scrubForExternalOutput(text) {
    if (typeof text !== 'string') return text;
    let out = text;
    if (this._activePinShadow && this._activePinShadow.length >= 4) {
      out = out.split(this._activePinShadow).join('[REDACTED_PIN]');
    }
    if (this._state?.llmConfig?.apiKey && this._state.llmConfig.apiKey.length >= 6) {
      out = out.split(this._state.llmConfig.apiKey).join('[REDACTED_API_KEY]');
    }
    return out;
  }

  getState() {
    this._ensureUnlocked();
    return JSON.parse(JSON.stringify(this._state));
  }

  updateState(partialUpdater) {
    this._ensureUnlocked();
    const next =
      typeof partialUpdater === 'function'
        ? partialUpdater(this.getState())
        : { ...this._state, ...partialUpdater };
    this._state = next;
    this.save();
    return this.getState();
  }

  save() {
    this._ensureUnlocked();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this._derivedKey, iv);
    const plaintext = JSON.stringify(this._state);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const envelope = {
      version: 1,
      kdf: 'scrypt-aes-256-gcm',
      salt: this._salt.toString('hex'),
      verifier: this._pinVerifierHash.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      ciphertext: encrypted.toString('hex'),
    };
    fs.writeFileSync(this.vaultPath, JSON.stringify(envelope, null, 2), 'utf8');
  }

  _decryptPayload(ciphertextHex, ivHex, authTagHex) {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      this._derivedKey,
      Buffer.from(ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(ciphertextHex, 'hex')),
      decipher.final(),
    ]);
    return JSON.parse(decrypted.toString('utf8'));
  }

  _ensureUnlocked() {
    if (!this.isUnlocked()) {
      throw new Error('VAULT_LOCKED: Unlock vault with startup PIN first.');
    }
  }
}
