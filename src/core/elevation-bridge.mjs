/**
 * AegisWin Encrypted Cross-Integrity IPC Job Bridge (`./data/jobs/`)
 * Solves the Windows Medium-Integrity (Standard User) -> High-Integrity (Admin UAC)
 * stdout/stderr isolation boundary without exposing unauthenticated pipes or modifiable CLI scripts.
 *
 * - Standard process writes an AES-256-GCM authenticated job request (`<jobId>.req.enc`)
 * - Spawns `aegis-win.exe --elevate-job <jobId>` via ShellExecuteW("runas")
 * - Elevated process verifies the AES-GCM authTag, executes the tool, and writes `<jobId>.res.enc`
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export class ElevationIpcBridge {
  constructor(vault) {
    this.vault = vault;
    this.jobsDir = path.join(this.vault.dataDir, 'jobs');
  }

  createEncryptedJob({ pluginId, toolId, args = {} }) {
    if (!this.vault.isUnlocked()) {
      throw new Error('VAULT_LOCKED: Cannot create elevation job while vault is locked.');
    }
    fs.mkdirSync(this.jobsDir, { recursive: true });
    const jobId = `JOB-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const payload = {
      jobId,
      pluginId,
      toolId,
      args,
      issuedAt: new Date().toISOString(),
      nonce: crypto.randomBytes(12).toString('hex'),
    };

    const reqPath = path.join(this.jobsDir, `${jobId}.req.enc`);
    this._writeEncryptedFile(reqPath, payload);

    return {
      jobId,
      reqPath,
      uacCommand: `aegis-win.exe --elevate-job ${jobId}`,
    };
  }

  executeElevatedJobFile(jobId, toolExecutor) {
    const reqPath = path.join(this.jobsDir, `${jobId}.req.enc`);
    if (!fs.existsSync(reqPath)) {
      throw new Error(`ELEVATION_JOB_NOT_FOUND: ${jobId}`);
    }
    const jobRequest = this._readEncryptedFile(reqPath);
    const output = toolExecutor(jobRequest);

    const resPath = path.join(this.jobsDir, `${jobId}.res.enc`);
    const resultEnvelope = {
      jobId: jobRequest.jobId,
      pluginId: jobRequest.pluginId,
      toolId: jobRequest.toolId,
      completedAt: new Date().toISOString(),
      output,
    };
    this._writeEncryptedFile(resPath, resultEnvelope);
    return resultEnvelope;
  }

  collectJobResult(jobId, cleanup = true) {
    const reqPath = path.join(this.jobsDir, `${jobId}.req.enc`);
    const resPath = path.join(this.jobsDir, `${jobId}.res.enc`);
    if (!fs.existsSync(resPath)) {
      throw new Error(`ELEVATION_RESULT_PENDING: ${jobId}`);
    }
    const result = this._readEncryptedFile(resPath);
    if (cleanup) {
      if (fs.existsSync(reqPath)) fs.unlinkSync(reqPath);
      if (fs.existsSync(resPath)) fs.unlinkSync(resPath);
    }
    return result;
  }

  _writeEncryptedFile(filePath, dataObj) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.vault._derivedKey, iv);
    const plaintext = JSON.stringify(dataObj);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    fs.writeFileSync(
      filePath,
      JSON.stringify({
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
        ciphertext: encrypted.toString('hex'),
      }),
      'utf8'
    );
  }

  _readEncryptedFile(filePath) {
    const raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    try {
      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        this.vault._derivedKey,
        Buffer.from(raw.iv, 'hex')
      );
      decipher.setAuthTag(Buffer.from(raw.authTag, 'hex'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(raw.ciphertext, 'hex')),
        decipher.final(),
      ]);
      return JSON.parse(decrypted.toString('utf8'));
    } catch {
      throw new Error('TAMPER_DETECTED: Elevated IPC job file failed AES-256-GCM authentication check.');
    }
  }
}
