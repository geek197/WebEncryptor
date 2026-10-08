import { argon2id } from 'hash-wasm';

globalThis.argon2id = argon2id;

const DEFAULT_PARAMS = { t: 10, p: 1, m: 65536, steps: 1000 };

let currentMode = 'encrypt';
let lastCiphertext = '';
let cancelRequested = false;
let paramsVisible = false;

function toggleParams() {
    paramsVisible = !paramsVisible;
    document.getElementById('paramFields').style.display = paramsVisible ? '' : 'none';
    document.getElementById('paramToggleBtn').innerHTML = (paramsVisible ? '&#9662;' : '&#9656;') + ' Custom parameters';
}

function setMode(mode) {
    currentMode = mode;
    document.getElementById('btnEncrypt').classList.toggle('active', mode === 'encrypt');
    document.getElementById('btnDecrypt').classList.toggle('active', mode === 'decrypt');
    document.getElementById('btnAction').textContent = mode === 'encrypt' ? 'Encrypt' : 'Decrypt';
    document.getElementById('outputLabel').textContent = mode === 'encrypt' ? 'Ciphertext' : 'Plain Text';
    document.getElementById('plainTextField').style.display = mode === 'encrypt' ? '' : 'none';
    document.getElementById('cipherTextField').style.display = mode === 'decrypt' ? '' : 'none';
    document.getElementById('paramToggle').style.display = mode === 'encrypt' ? '' : 'none';
    document.getElementById('paramFields').style.display = (mode === 'encrypt' && paramsVisible) ? '' : 'none';
    hideError();
    resetOutput();
    updatePasswordStrength();
}

function estimatePasswordStrength(password) {
    if (!password) return { level: 0, label: '', percent: 0 };
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/[0-9]/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;
    poolSize = poolSize || 1;
    const entropy = password.length * Math.log2(poolSize);

    let level, label;
    if (entropy < 28) { level = 1; label = 'Very Weak'; }
    else if (entropy < 36) { level = 2; label = 'Weak'; }
    else if (entropy < 60) { level = 3; label = 'Fair'; }
    else if (entropy < 100) { level = 4; label = 'Strong'; }
    else { level = 5; label = 'Very Strong'; }

    const percent = Math.max(6, Math.min(100, Math.round((entropy / 100) * 100)));
    return { level, label, percent };
}

function updatePasswordStrength() {
    const meter = document.getElementById('strengthMeter');
    if (currentMode !== 'encrypt') {
        meter.classList.remove('visible');
        return;
    }
    const password = document.getElementById('password').value;
    const fill = document.getElementById('strengthBarFill');
    const label = document.getElementById('strengthLabel');

    if (!password) {
        meter.classList.remove('visible');
        return;
    }

    const { level, label: text, percent } = estimatePasswordStrength(password);
    meter.classList.add('visible');
    fill.style.width = percent + '%';
    fill.className = 'strength-bar-fill strength-' + level;
    label.textContent = text;
}

function showProgress(text) {
    const container = document.getElementById('progressContainer');
    const bar = document.getElementById('progressBar');
    document.getElementById('progressText').textContent = text;
    bar.className = 'progress-bar-fill indeterminate';
    bar.style.width = '';
    container.classList.add('visible');
}

function setProgress(text, percent) {
    const container = document.getElementById('progressContainer');
    const bar = document.getElementById('progressBar');
    document.getElementById('progressText').textContent = text;
    bar.className = 'progress-bar-fill';
    bar.style.width = percent + '%';
    container.classList.add('visible');
}

function hideProgress() {
    document.getElementById('progressContainer').classList.remove('visible');
    const btn = document.getElementById('cancelBtn');
    btn.classList.remove('visible');
    btn.disabled = false;
    btn.textContent = 'Cancel';
}

function showCancel() {
    cancelRequested = false;
    const btn = document.getElementById('cancelBtn');
    btn.disabled = false;
    btn.textContent = 'Cancel';
    btn.classList.add('visible');
}

function cancelOperation() {
    cancelRequested = true;
    const btn = document.getElementById('cancelBtn');
    btn.disabled = true;
    btn.textContent = 'Cancelling...';
}

function showError(msg) {
    const el = document.getElementById('errorMsg');
    el.textContent = msg;
    el.classList.add('visible');
}

function hideError() {
    document.getElementById('errorMsg').classList.remove('visible');
}

function resetOutput() {
    const el = document.getElementById('outputText');
    el.innerHTML = '<span class="placeholder">Output will appear here...</span>';
    document.getElementById('copyBtn').classList.remove('visible', 'copied');
    document.getElementById('downloadRow').classList.remove('visible');
    lastCiphertext = '';
}

function clearAll() {
    document.getElementById('password').value = '';
    document.getElementById('passwordConfirm').value = '';
    document.getElementById('plainText').value = '';
    document.getElementById('cipherText').value = '';
    hideError();
    hideProgress();
    resetOutput();
    updatePasswordStrength();
}

function setOutput(text) {
    const el = document.getElementById('outputText');
    el.textContent = text;
    document.getElementById('copyBtn').classList.add('visible');
    document.getElementById('copyBtn').classList.remove('copied');
}

async function copyOutput() {
    const text = document.getElementById('outputText').textContent;
    if (!text || text.includes('Output will appear here')) return;
    try {
        await navigator.clipboard.writeText(text);
        const btn = document.getElementById('copyBtn');
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
        }, 1500);
    } catch (e) {
        showError('Failed to copy to clipboard.');
    }
}

async function processAction() {
    hideError();
    resetOutput();
    cancelRequested = false;

    const password = document.getElementById('password').value;
    const input = currentMode === 'encrypt'
        ? document.getElementById('plainText').value
        : document.getElementById('cipherText').value;

    if (!password) {
        showError('Password is required.');
        return;
    }
    if (password !== document.getElementById('passwordConfirm').value) {
        showError('Passwords do not match.');
        return;
    }
    if (!input) {
        showError(currentMode === 'encrypt' ? 'Plain text is required.' : 'Ciphertext is required.');
        return;
    }

    document.getElementById('btnAction').disabled = true;

    try {
        if (currentMode === 'encrypt') {
            await encrypt(password, input);
        } else {
            await decrypt(password, input);
        }
    } catch (e) {
        showError(e.message);
    } finally {
        document.getElementById('btnAction').disabled = false;
        hideProgress();
    }
}

function readParams() {
    const t = parseInt(document.getElementById('paramT').value, 10);
    const p = parseInt(document.getElementById('paramP').value, 10);
    const mib = parseInt(document.getElementById('paramM').value, 10);
    const steps = parseInt(document.getElementById('paramSteps').value, 10);

    if (!Number.isInteger(t) || t < 1 || t > 1000) {
        throw new Error('Iterations (t) must be an integer between 1 and 1000.');
    }
    if (!Number.isInteger(p) || p < 1 || p > 64) {
        throw new Error('Parallelism (p) must be an integer between 1 and 64.');
    }
    if (!Number.isInteger(mib) || mib < 8 || mib > 2048) {
        throw new Error('Memory must be an integer between 8 and 2048 MiB.');
    }
    if (!Number.isInteger(steps) || steps < 1 || steps > 1000000) {
        throw new Error('Steps must be an integer between 1 and 1000000.');
    }
    return { t, p, m: mib * 1024, steps };
}

function sanitizeDecryptParams(parsed) {
    const t = parseInt(parsed.t, 10);
    const p = parseInt(parsed.p, 10);
    const m = parseInt(parsed.m, 10);
    if (Number.isInteger(t) && t < 1 || Number.isInteger(t) && t > 100000) {
        throw new Error('Ciphertext contains invalid iterations (t).');
    }
    if (Number.isInteger(p) && p < 1 || Number.isInteger(p) && p > 64) {
        throw new Error('Ciphertext contains invalid parallelism (p).');
    }
    if (Number.isInteger(m) && m < 8 * 1024 || Number.isInteger(m) && m > 2 * 1024 * 1024) {
        throw new Error('Ciphertext contains invalid memory size (m).');
    }
    const steps = parseInt(parsed.steps, 10);
    if (Number.isInteger(steps) && steps < 1 || Number.isInteger(steps) && steps > 1000000) {
        throw new Error('Ciphertext contains invalid steps count.');
    }
    return {
        t: Number.isInteger(t) ? t : DEFAULT_PARAMS.t,
        p: Number.isInteger(p) ? p : DEFAULT_PARAMS.p,
        m: Number.isInteger(m) ? m : DEFAULT_PARAMS.m,
        steps: Number.isInteger(steps) ? steps : 1
    };
}

function formatDuration(ms) {
    if (ms < 1000) return Math.round(ms) + ' ms';
    const s = ms / 1000;
    if (s < 60) return s.toFixed(1) + ' s';
    if (s < 3600) { const t = Math.round(s); return Math.floor(t / 60) + ' min ' + (t % 60) + ' s'; }
    if (s < 86400) { const t = Math.round(s / 60); return Math.floor(t / 60) + ' h ' + (t % 60) + ' min'; }
    const t = Math.round(s / 3600);
    return Math.floor(t / 24) + ' d ' + (t % 24) + ' h';
}

async function deriveKey(password, salt, params) {
    let input = password;
    const stepTimes = [];
    if (params.steps > 1) showCancel();
    for (let step = 1; step <= params.steps; step++) {
        if (cancelRequested) throw new Error('Operation cancelled.');
        if (params.steps === 1) {
            showProgress(`Deriving key with Argon2id (t=${params.t}, p=${params.p}, m=${params.m / 1024} MiB)...`);
        } else {
            let text = `Deriving key with Argon2id (step ${step}/${params.steps})...`;
            if (stepTimes.length > 0) {
                const mean = stepTimes.reduce((a, b) => a + b, 0) / stepTimes.length;
                text += ` ~${formatDuration(mean * (params.steps - step + 1))} remaining`;
            }
            setProgress(text, ((step - 1) / params.steps) * 100);
        }
        await yieldToUI();
        const stepStart = performance.now();
        input = await argon2id({
            password: input,
            salt: salt,
            iterations: params.t,
            parallelism: params.p,
            memorySize: params.m,
            hashLength: 32,
            outputType: 'binary'
        });
        stepTimes.push(performance.now() - stepStart);
    }
    if (params.steps > 1) {
        setProgress('Key derivation complete.', 100);
    }
    return crypto.subtle.importKey('raw', input, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function toB64(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}

function fromB64(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function encrypt(password, plaintext) {
    const params = readParams();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await deriveKey(password, salt, params);

    showProgress('Encrypting with AES-GCM...');
    await yieldToUI();

    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        enc.encode(plaintext)
    );

    const output = JSON.stringify({
        s: toB64(salt),
        i: toB64(iv),
        t: params.t,
        p: params.p,
        m: params.m,
        steps: params.steps,
        d: toB64(new Uint8Array(ciphertext))
    });
    lastCiphertext = output;
    setOutput(output);
    document.getElementById('downloadRow').classList.add('visible');
}

async function decrypt(password, ciphertextJson) {
    let parsed;
    try {
        parsed = JSON.parse(ciphertextJson);
    } catch (e) {
        throw new Error('Invalid ciphertext format. Expected JSON with salt, IV, and data.');
    }

    if (!parsed.s || !parsed.i || !parsed.d) {
        throw new Error('Ciphertext is missing required fields (s, i, d).');
    }

    const params = sanitizeDecryptParams(parsed);
    const salt = fromB64(parsed.s);
    const iv = fromB64(parsed.i);
    const data = fromB64(parsed.d);

    const key = await deriveKey(password, salt, params);

    showProgress('Decrypting with AES-GCM...');
    await yieldToUI();

    let decrypted;
    try {
        decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            data
        );
    } catch (e) {
        throw new Error('Decryption failed. Wrong password or corrupted data.');
    }

    const dec = new TextDecoder();
    setOutput(dec.decode(decrypted));
}

function yieldToUI() {
    return new Promise(resolve => setTimeout(resolve, 0));
}

function downloadDecryptorHTML() {
    if (!lastCiphertext) return;
    const html = generateDecryptorHTML(lastCiphertext);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'encrypted-message.html';
    a.click();
    URL.revokeObjectURL(url);
}

function escapeScriptTag(str) {
    return str.replace(/<\/script/gi, '<\\/script');
}

function generateDecryptorHTML(ciphertext) {
    const escaped = ciphertext.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
    const bundle = escapeScriptTag(globalThis.__HE_BUNDLE__);
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
    <title>WebEncryptor - Decrypt</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #0f1117;
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        header {
            background: #161922;
            border-bottom: 1px solid #2a2d3a;
            padding: 16px 24px;
            text-align: center;
        }
        header h1 {
            font-size: 1.4rem;
            font-weight: 600;
            color: #7c8aff;
        }
        header p {
            font-size: 0.8rem;
            color: #6b7094;
            margin-top: 4px;
        }
        main {
            flex: 1;
            max-width: 720px;
            width: 100%;
            margin: 0 auto;
            padding: 24px 16px;
        }
        .field { margin-bottom: 16px; }
        .field label {
            display: block;
            font-size: 0.8rem;
            font-weight: 600;
            color: #8a8eb0;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .field input, .field textarea {
            width: 100%;
            background: #1a1d28;
            border: 1px solid #2a2d3a;
            border-radius: 8px;
            padding: 12px;
            color: #e0e0e0;
            font-size: 0.95rem;
            font-family: inherit;
            outline: none;
            transition: border-color 0.2s;
        }
        .field input:focus, .field textarea:focus { border-color: #7c8aff; }
        .field textarea { resize: vertical; min-height: 120px; }
        .btn-row { display: flex; gap: 10px; margin-bottom: 16px; }
        .btn-primary {
            flex: 1;
            padding: 12px;
            border: none;
            border-radius: 8px;
            background: #7c8aff;
            color: #fff;
            font-size: 0.95rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        .btn-primary:hover:not(:disabled) { background: #6570e0; }
        .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
        .progress-container { margin-bottom: 16px; display: none; }
        .progress-container.visible { display: block; }
        .progress-label {
            font-size: 0.8rem;
            color: #7c8aff;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .spinner {
            width: 14px; height: 14px;
            border: 2px solid #2a2d3a;
            border-top-color: #7c8aff;
            border-radius: 50%;
            animation: spin 0.7s linear infinite;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .progress-bar-track {
            height: 6px;
            background: #1a1d28;
            border-radius: 3px;
            overflow: hidden;
        }
        .progress-bar-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #7c8aff, #a78bfa);
            border-radius: 3px;
            transition: width 0.3s ease;
        }
        .progress-bar-fill.indeterminate {
            width: 30%;
            animation: indeterminate 1.2s ease-in-out infinite;
        }
        @keyframes indeterminate {
            0% { margin-left: -30%; }
            100% { margin-left: 100%; }
        }
        .btn-cancel {
            margin-top: 10px;
            padding: 6px 14px;
            border: 1px solid #5c2040;
            border-radius: 6px;
            background: transparent;
            color: #f87171;
            font-size: 0.8rem;
            cursor: pointer;
            display: none;
        }
        .btn-cancel.visible { display: inline-block; }
        .btn-cancel:hover:not(:disabled) { background: #2a1520; }
        .btn-cancel:disabled { opacity: 0.5; cursor: default; }
        .output-area {
            background: #1a1d28;
            border: 1px solid #2a2d3a;
            border-radius: 8px;
            padding: 12px;
            min-height: 80px;
            position: relative;
        }
        .output-area pre {
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 0.9rem;
            color: #c8cad8;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
            line-height: 1.5;
        }
        .copy-btn {
            position: absolute;
            top: 8px; right: 8px;
            padding: 4px 10px;
            border: 1px solid #2a2d3a;
            border-radius: 6px;
            background: #161922;
            color: #6b7094;
            font-size: 0.75rem;
            cursor: pointer;
            transition: all 0.2s;
            display: none;
        }
        .copy-btn.visible { display: block; }
        .copy-btn:hover { border-color: #7c8aff; color: #7c8aff; }
        .copy-btn.copied { border-color: #34d399; color: #34d399; }
        .error-msg {
            background: #2a1520;
            border: 1px solid #5c2040;
            border-radius: 8px;
            padding: 10px 12px;
            margin-bottom: 16px;
            font-size: 0.85rem;
            color: #f87171;
            display: none;
        }
        .error-msg.visible { display: block; }
        footer {
            background: #161922;
            border-top: 1px solid #2a2d3a;
            padding: 14px 24px;
            text-align: center;
        }
        footer p {
            font-size: 0.75rem;
            color: #4a4e6a;
            line-height: 1.6;
        }
        footer code {
            background: #1a1d28;
            padding: 1px 5px;
            border-radius: 3px;
            font-size: 0.72rem;
            color: #7c8aff;
        }
    </style>
</head>
<body>
<header>
    <h1>Encrypted Message</h1>
    <p>Enter the password to decrypt this message</p>
</header>
<main>
    <div class="field">
        <label for="password">Password</label>
        <input type="password" id="password" placeholder="Enter password" autocomplete="off">
    </div>
    <div class="field">
        <label for="passwordConfirm">Confirm Password</label>
        <input type="password" id="passwordConfirm" placeholder="Re-enter password" autocomplete="off">
    </div>
    <div class="btn-row">
        <button class="btn-primary" id="btnDecrypt" onclick="decrypt()">Decrypt</button>
    </div>
    <div class="progress-container" id="progressContainer">
        <div class="progress-label">
            <div class="spinner"></div>
            <span id="progressText">Deriving key...</span>
        </div>
        <div class="progress-bar-track">
            <div class="progress-bar-fill indeterminate" id="progressBar"></div>
        </div>
        <button class="btn-cancel" id="cancelBtn" onclick="cancelOperation()">Cancel</button>
    </div>
    <div class="error-msg" id="errorMsg"></div>
    <div class="field">
        <label for="outputText">Decrypted Text</label>
        <div class="output-area">
            <pre id="outputText">Encrypted data is embedded in this file. Enter the password above and click Decrypt.</pre>
            <button class="copy-btn" id="copyBtn" onclick="copyOutput()">Copy</button>
        </div>
    </div>
</main>
<footer>
    <p>
        Key derivation: <code>Argon2id</code> (parameters embedded in the ciphertext) &mdash;
        Encryption: <code>AES-GCM</code>, 256-bit key, 12-byte random IV<br>
        All operations run locally in your browser via the <code>Web Crypto API</code> and <code>hash-wasm</code>. No data is transmitted.
    </p>
</footer>
<script>${bundle}</script>
<script>
    const CIPHERTEXT = '${escaped}';

    function showProgress(text) {
        document.getElementById('progressText').textContent = text;
        document.getElementById('progressBar').className = 'progress-bar-fill indeterminate';
        document.getElementById('progressBar').style.width = '';
        document.getElementById('progressContainer').classList.add('visible');
    }
    function setProgress(text, percent) {
        document.getElementById('progressText').textContent = text;
        const bar = document.getElementById('progressBar');
        bar.className = 'progress-bar-fill';
        bar.style.width = percent + '%';
        document.getElementById('progressContainer').classList.add('visible');
    }
    let cancelRequested = false;
    function hideProgress() {
        document.getElementById('progressContainer').classList.remove('visible');
        const btn = document.getElementById('cancelBtn');
        btn.classList.remove('visible');
        btn.disabled = false;
        btn.textContent = 'Cancel';
    }
    function showCancel() {
        cancelRequested = false;
        const btn = document.getElementById('cancelBtn');
        btn.disabled = false;
        btn.textContent = 'Cancel';
        btn.classList.add('visible');
    }
    function cancelOperation() {
        cancelRequested = true;
        const btn = document.getElementById('cancelBtn');
        btn.disabled = true;
        btn.textContent = 'Cancelling...';
    }
    function showError(msg) {
        const el = document.getElementById('errorMsg');
        el.textContent = msg;
        el.classList.add('visible');
    }
    function setOutput(text) {
        document.getElementById('outputText').textContent = text;
        const btn = document.getElementById('copyBtn');
        btn.classList.add('visible');
        btn.classList.remove('copied');
    }
    async function copyOutput() {
        const text = document.getElementById('outputText').textContent;
        try {
            await navigator.clipboard.writeText(text);
            const btn = document.getElementById('copyBtn');
            btn.textContent = 'Copied!';
            btn.classList.add('copied');
            setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1500);
        } catch (e) { showError('Failed to copy to clipboard.'); }
    }
    function formatDuration(ms) {
        if (ms < 1000) return Math.round(ms) + ' ms';
        const s = ms / 1000;
        if (s < 60) return s.toFixed(1) + ' s';
        if (s < 3600) { const t = Math.round(s); return Math.floor(t / 60) + ' min ' + (t % 60) + ' s'; }
        if (s < 86400) { const t = Math.round(s / 60); return Math.floor(t / 60) + ' h ' + (t % 60) + ' min'; }
        const t = Math.round(s / 3600);
        return Math.floor(t / 24) + ' d ' + (t % 24) + ' h';
    }
    async function deriveKey(password, salt, params) {
        let input = password;
        const stepTimes = [];
        if (params.steps > 1) showCancel();
        for (let step = 1; step <= params.steps; step++) {
            if (cancelRequested) throw new Error('Operation cancelled.');
            if (params.steps === 1) {
                showProgress('Deriving key with Argon2id (t=' + params.t + ', p=' + params.p + ', m=' + (params.m / 1024) + ' MiB)...');
            } else {
                let text = 'Deriving key with Argon2id (step ' + step + '/' + params.steps + ')...';
                if (stepTimes.length > 0) {
                    const mean = stepTimes.reduce((a, b) => a + b, 0) / stepTimes.length;
                    text += ' ~' + formatDuration(mean * (params.steps - step + 1)) + ' remaining';
                }
                setProgress(text, ((step - 1) / params.steps) * 100);
            }
            await new Promise(r => setTimeout(r, 0));
            const stepStart = performance.now();
            input = await argon2id({
                password: input,
                salt: salt,
                iterations: params.t,
                parallelism: params.p,
                memorySize: params.m,
                hashLength: 32,
                outputType: 'binary'
            });
            stepTimes.push(performance.now() - stepStart);
        }
        if (params.steps > 1) setProgress('Key derivation complete.', 100);
        return crypto.subtle.importKey('raw', input, { name: 'AES-GCM' }, false, ['decrypt']);
    }
    async function decrypt() {
        document.getElementById('errorMsg').classList.remove('visible');
        if (!crypto.subtle) {
            showError('Web Crypto API (crypto.subtle) is unavailable in this context. Open this file directly (file://) or serve it over http://localhost or HTTPS.');
            return;
        }
        cancelRequested = false;
        const password = document.getElementById('password').value;
        if (!password) { showError('Password is required.'); return; }
        if (password !== document.getElementById('passwordConfirm').value) { showError('Passwords do not match.'); return; }
        document.getElementById('btnDecrypt').disabled = true;
        try {
            const parsed = JSON.parse(CIPHERTEXT);
            if (!parsed.s || !parsed.i || !parsed.d) throw new Error('Invalid ciphertext data.');
            const cp = {
                t: parseInt(parsed.t, 10),
                p: parseInt(parsed.p, 10),
                m: parseInt(parsed.m, 10),
                steps: parseInt(parsed.steps, 10)
            };
            if (Number.isInteger(cp.t) && cp.t < 1 || Number.isInteger(cp.t) && cp.t > 100000) throw new Error('Ciphertext contains invalid iterations (t).');
            if (Number.isInteger(cp.p) && cp.p < 1 || Number.isInteger(cp.p) && cp.p > 64) throw new Error('Ciphertext contains invalid parallelism (p).');
            if (Number.isInteger(cp.m) && cp.m < 8 * 1024 || Number.isInteger(cp.m) && cp.m > 2 * 1024 * 1024) throw new Error('Ciphertext contains invalid memory size (m).');
            if (Number.isInteger(cp.steps) && cp.steps < 1 || Number.isInteger(cp.steps) && cp.steps > 1000000) throw new Error('Ciphertext contains invalid steps count.');
            const params = {
                t: Number.isInteger(cp.t) ? cp.t : 10,
                p: Number.isInteger(cp.p) ? cp.p : 1,
                m: Number.isInteger(cp.m) ? cp.m : 65536,
                steps: Number.isInteger(cp.steps) ? cp.steps : 1
            };
            const salt = Uint8Array.from(atob(parsed.s), c => c.charCodeAt(0));
            const iv = Uint8Array.from(atob(parsed.i), c => c.charCodeAt(0));
            const data = Uint8Array.from(atob(parsed.d), c => c.charCodeAt(0));
            const key = await deriveKey(password, salt, params);
            showProgress('Decrypting with AES-GCM...');
            await new Promise(r => setTimeout(r, 50));
            const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, data);
            setOutput(new TextDecoder().decode(decrypted));
        } catch (e) {
            if (e.message.includes('Data and error tag')) {
                showError('Decryption failed. Wrong password or corrupted data.');
            } else {
                showError(e.message);
            }
        } finally {
            document.getElementById('btnDecrypt').disabled = false;
            hideProgress();
        }
    }
<\/script>
</body>
</html>`;
}

globalThis.setMode = setMode;
globalThis.processAction = processAction;
globalThis.clearAll = clearAll;
globalThis.copyOutput = copyOutput;
globalThis.updatePasswordStrength = updatePasswordStrength;
globalThis.downloadDecryptorHTML = downloadDecryptorHTML;
globalThis.cancelOperation = cancelOperation;
globalThis.toggleParams = toggleParams;

if (!globalThis.crypto || !globalThis.crypto.subtle) {
    showError('Web Crypto API (crypto.subtle) is unavailable in this context. Open this page via file://, http://localhost, or HTTPS. Plain http:// on a LAN IP or other hostname disables it.');
}
