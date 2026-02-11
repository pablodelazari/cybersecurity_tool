/* ========================================
   SecuriTool — Frontend Logic
   ======================================== */

// State
let currentScanId = null;
let pollInterval = null;

// ── Matrix Background Animation ──
function initMatrix() {
    const canvas = document.getElementById('matrix-bg');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
    const fontSize = 14;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = Array(columns).fill(1);

    function draw() {
        ctx.fillStyle = 'rgba(10, 14, 23, 0.08)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#00ffcc';
        ctx.font = `${fontSize}px monospace`;

        for (let i = 0; i < drops.length; i++) {
            const char = chars[Math.floor(Math.random() * chars.length)];
            ctx.fillText(char, i * fontSize, drops[i] * fontSize);

            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            drops[i]++;
        }
    }

    setInterval(draw, 50);

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ── Scan Management ──
function getSelectedModules() {
    const checkboxes = document.querySelectorAll('.module-card input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => cb.value);
}

async function startScan() {
    const target = document.getElementById('target-input').value.trim();
    if (!target) {
        shakeElement(document.querySelector('.input-wrapper'));
        return;
    }

    const modules = getSelectedModules();
    if (modules.length === 0) {
        alert('Select at least one scan module.');
        return;
    }

    const btn = document.getElementById('scan-btn');
    btn.disabled = true;
    btn.classList.add('scanning');
    btn.querySelector('span').textContent = 'Scanning...';

    // Show progress
    document.getElementById('progress-section').classList.remove('hidden');
    document.getElementById('results-section').classList.add('hidden');

    // Init progress module tags
    const moduleNames = {
        ports: 'Port Scanner',
        headers: 'Security Headers',
        ssl: 'SSL/TLS',
        dns: 'DNS Enum',
        tech: 'Tech Detection',
        vulns: 'Vuln Scanner',
        recon: 'Recon / Files',
        waf: 'WAF Detection'
    };

    const progressModules = document.getElementById('progress-modules');
    progressModules.innerHTML = modules.map(m =>
        `<span class="progress-module-tag" data-module="${m}">${moduleNames[m] || m}</span>`
    ).join('');

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, modules })
        });

        const data = await response.json();
        if (data.error) {
            showError(data.error);
            resetButton();
            return;
        }

        currentScanId = data.scan_id;
        startPolling();

    } catch (err) {
        showError('Failed to connect to the server. Is the backend running?');
        resetButton();
    }
}

function startPolling() {
    if (pollInterval) clearInterval(pollInterval);

    pollInterval = setInterval(async () => {
        try {
            const response = await fetch(`/api/scan/${currentScanId}`);
            const data = await response.json();

            updateProgress(data);

            if (data.status === 'completed') {
                clearInterval(pollInterval);
                pollInterval = null;
                renderResults(data);
                resetButton();
            }
        } catch (err) {
            console.error('Polling error:', err);
        }
    }, 500);
}

function updateProgress(data) {
    document.getElementById('progress-bar').style.width = `${data.progress}%`;
    document.getElementById('progress-pct').textContent = `${data.progress}%`;
    document.getElementById('progress-status').textContent = data.current_module || 'Processing...';

    // Update module tags
    data.modules_completed.forEach(m => {
        const tag = document.querySelector(`.progress-module-tag[data-module="${m}"]`);
        if (tag) {
            tag.classList.remove('active');
            tag.classList.add('done');
        }
    });

    // Mark current module as active
    const allTags = document.querySelectorAll('.progress-module-tag');
    allTags.forEach(tag => {
        const mod = tag.dataset.module;
        if (!data.modules_completed.includes(mod) && data.current_module && data.current_module.toLowerCase().includes(mod)) {
            tag.classList.add('active');
        }
    });
}

function resetButton() {
    const btn = document.getElementById('scan-btn');
    btn.disabled = false;
    btn.classList.remove('scanning');
    btn.querySelector('span').textContent = 'Launch Scan';
}

function showError(message) {
    const container = document.getElementById('results-container');
    container.innerHTML = `<div class="error-banner">⚠️ ${escapeHTML(message)}</div>`;
    document.getElementById('results-section').classList.remove('hidden');
}

// ── Results Rendering ──
function renderResults(scan) {
    const container = document.getElementById('results-container');
    container.innerHTML = '';

    document.getElementById('result-target').textContent = `Target: ${scan.target}`;
    document.getElementById('result-time').textContent = `⏱ ${scan.elapsed}s`;
    document.getElementById('results-section').classList.remove('hidden');

    const renderers = {
        headers: renderHeaderResults,
        ssl: renderSSLResults,
        ports: renderPortResults,
        dns: renderDNSResults,
        tech: renderTechResults,
        vulns: renderVulnResults,
        recon: renderReconResults,
        waf: renderWAFResults
    };

    const moduleIcons = {
        ports: '🔌',
        headers: '🛡️',
        ssl: '🔒',
        dns: '🌐',
        tech: '🔧',
        vulns: '⚠️',
        recon: '🔍',
        waf: '🛡️'
    };

    const moduleNames2 = {
        ports: 'Port Scanner',
        headers: 'Security Headers',
        ssl: 'SSL/TLS Analysis',
        dns: 'DNS Enumeration',
        tech: 'Technology Detection',
        vulns: 'Vulnerability Scanner',
        recon: 'Recon / File Discovery',
        waf: 'WAF Detection'
    };

    let delay = 0;
    for (const [key, data] of Object.entries(scan.results)) {
        const card = document.createElement('div');
        card.className = 'result-card open';
        card.style.animationDelay = `${delay}ms`;

        const riskLevel = data.risk_level || data.grade || 'info';
        const riskClass = riskLevel.toLowerCase().replace('+', '');

        card.innerHTML = `
            <div class="result-card-header" onclick="toggleCard(this)">
                <div class="result-card-title">
                    <span class="icon">${moduleIcons[key] || '📋'}</span>
                    <h3>${moduleNames2[key] || key}</h3>
                </div>
                <div style="display:flex;align-items:center;gap:12px;">
                    <span class="risk-badge ${riskClass}">${riskLevel}</span>
                    <svg class="chevron" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                </div>
            </div>
            <div class="result-card-body" id="result-body-${key}"></div>
        `;

        container.appendChild(card);

        // Render specific content
        const body = card.querySelector(`#result-body-${key}`);
        if (data.error) {
            body.innerHTML = `<div class="error-banner">${escapeHTML(data.error)}</div>`;
        } else if (renderers[key]) {
            renderers[key](body, data);
        } else {
            body.innerHTML = `<pre style="color:var(--text-secondary);font-family:var(--font-mono);font-size:0.8rem;overflow-x:auto;">${escapeHTML(JSON.stringify(data, null, 2))}</pre>`;
        }

        delay += 100;
    }

    // Scroll to results
    document.getElementById('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function toggleCard(header) {
    header.parentElement.classList.toggle('open');
}

// ── Module-Specific Renderers ──

function renderHeaderResults(body, data) {
    const gradeClass = `grade-${data.grade.toLowerCase().replace('+', '-plus')}`;

    let html = `
        <div class="grade-display">
            <div class="grade-letter ${gradeClass}">${data.grade}</div>
            <div class="grade-info">
                <div class="score-text">${data.score}/${data.max_score} points — ${data.percentage}% compliance</div>
                <div class="grade-bar-bg">
                    <div class="grade-bar-fill" style="width:${data.percentage}%;background:${getGradeColor(data.grade)};"></div>
                </div>
            </div>
        </div>
    `;

    if (data.headers_found.length > 0) {
        html += `<div class="section-label">✅ Headers Present (${data.headers_found.length})</div>`;
        html += '<table class="data-table"><thead><tr><th>Header</th><th>Value</th><th>Strength</th></tr></thead><tbody>';
        for (const h of data.headers_found) {
            const strengthClass = h.strength === 'strong' ? 'status-present' : 'status-weak';
            html += `<tr>
                <td style="color:var(--text-primary);font-weight:500">${h.name}</td>
                <td>${truncate(h.value, 60)}</td>
                <td class="${strengthClass}">${h.strength === 'strong' ? '✅ Strong' : '⚠️ Weak'}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    if (data.headers_missing.length > 0) {
        html += `<div class="section-label">❌ Headers Missing (${data.headers_missing.length})</div>`;
        html += '<table class="data-table"><thead><tr><th>Header</th><th>Severity</th><th>Recommended</th></tr></thead><tbody>';
        for (const h of data.headers_missing) {
            html += `<tr>
                <td style="color:var(--text-primary);font-weight:500">${h.name}</td>
                <td class="status-missing">${h.severity.toUpperCase()}</td>
                <td>${truncate(h.recommended, 50)}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    if (data.info_leaks && data.info_leaks.length > 0) {
        html += `<div class="section-label">🔍 Information Leakage</div>`;
        for (const leak of data.info_leaks) {
            html += `<div class="finding severity-low">
                <div class="finding-header">
                    <span class="finding-title">${leak.header}: ${escapeHTML(leak.value)}</span>
                </div>
                <div class="finding-detail">${leak.risk}</div>
            </div>`;
        }
    }

    body.innerHTML = html;
}

function renderSSLResults(body, data) {
    let html = '';

    const cert = data.certificate || {};
    if (cert.common_name) {
        html += `<div class="ssl-grid">
            <div class="ssl-item"><div class="ssl-item-label">Common Name</div><div class="ssl-item-value">${escapeHTML(cert.common_name)}</div></div>
            <div class="ssl-item"><div class="ssl-item-label">Issuer</div><div class="ssl-item-value">${escapeHTML(cert.issuer || 'N/A')}</div></div>
            <div class="ssl-item"><div class="ssl-item-label">Valid Until</div><div class="ssl-item-value">${escapeHTML(cert.valid_until || 'N/A')}</div></div>
            <div class="ssl-item"><div class="ssl-item-label">Days Until Expiry</div><div class="ssl-item-value" style="color:${cert.days_until_expiry > 90 ? 'var(--green)' : cert.days_until_expiry > 30 ? 'var(--amber)' : 'var(--red)'}">${cert.days_until_expiry ?? 'N/A'}</div></div>
            <div class="ssl-item"><div class="ssl-item-label">TLS Version</div><div class="ssl-item-value">${escapeHTML(data.tls_version || 'N/A')}</div></div>
            <div class="ssl-item"><div class="ssl-item-label">Cipher Suite</div><div class="ssl-item-value">${escapeHTML(data.cipher_suite?.name || 'N/A')} (${data.cipher_suite?.bits || '?'}-bit)</div></div>
        </div>`;
    }

    if (cert.san && cert.san.length > 0) {
        html += `<div class="section-label">Subject Alternative Names</div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;">
            ${cert.san.map(s => `<span class="tag">${escapeHTML(s)}</span>`).join('')}
        </div>`;
    }

    if (data.issues && data.issues.length > 0) {
        html += `<div class="section-label">Issues Found</div>`;
        html += renderFindings(data.issues);
    } else {
        html += `<div class="section-label" style="color:var(--green)">✅ No SSL/TLS issues detected</div>`;
    }

    body.innerHTML = html;
}

function renderPortResults(body, data) {
    let html = `
        <div class="stats-row">
            <div class="stat-box">
                <div class="stat-value" style="color:var(--cyan)">${data.ports_scanned}</div>
                <div class="stat-label">Ports Scanned</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--green)">${data.open_count}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">${data.target_ip}</div>
                <div class="stat-label">Target IP</div>
            </div>
        </div>
    `;

    if (data.open_ports && data.open_ports.length > 0) {
        html += `<div class="section-label">Open Ports</div>`;
        for (const port of data.open_ports) {
            html += `<div class="port-item">
                <span class="port-number">${port.port}</span>
                <span class="port-service">${escapeHTML(port.service)}</span>
                <span class="port-state">OPEN</span>
            </div>`;
        }
    } else {
        html += `<div class="section-label" style="color:var(--green)">✅ No open ports found in scanned range</div>`;
    }

    body.innerHTML = html;
}

function renderDNSResults(body, data) {
    let html = '';

    // DNS Records
    if (data.records) {
        html += `<div class="section-label">DNS Records</div><div class="dns-records-section">`;
        for (const [type, records] of Object.entries(data.records)) {
            if (records.length === 0) continue;
            html += `<div class="dns-record-type">${type}</div>`;
            for (const rec of records) {
                html += `<div class="dns-record-value">${escapeHTML(rec.value)}${rec.priority !== undefined ? ` (priority: ${rec.priority})` : ''}</div>`;
            }
        }
        html += '</div>';
    }

    // Subdomains
    if (data.subdomains && data.subdomains.length > 0) {
        html += `<div class="section-label">Subdomains Found (${data.subdomain_count})</div>
        <div class="subdomain-grid">
            ${data.subdomains.map(s => `
                <div class="subdomain-item">
                    <span class="domain">${escapeHTML(s.subdomain)}</span>
                    <span>${escapeHTML(s.ip)}</span>
                </div>
            `).join('')}
        </div>`;
    }

    // Issues
    if (data.issues && data.issues.length > 0) {
        html += `<div class="section-label">Security Findings</div>`;
        html += renderFindings(data.issues);
    }

    body.innerHTML = html;
}

function renderTechResults(body, data) {
    let html = '';

    // Server info
    if (data.server_info && Object.keys(data.server_info).length > 0) {
        html += `<div class="ssl-grid">`;
        for (const [key, value] of Object.entries(data.server_info)) {
            html += `<div class="ssl-item"><div class="ssl-item-label">${key.replace(/_/g, ' ')}</div><div class="ssl-item-value">${escapeHTML(value)}</div></div>`;
        }
        html += `</div>`;
    }

    // Technologies
    if (data.technologies && data.technologies.length > 0) {
        html += `<div class="section-label">Detected Technologies (${data.technologies.length})</div>`;
        html += '<div class="tech-grid">';
        for (const tech of data.technologies) {
            html += `<div class="tech-item">
                <div class="tech-name">${escapeHTML(tech.name)}</div>
                <div class="tech-category">${escapeHTML(tech.category)}</div>
            </div>`;
        }
        html += '</div>';
    } else {
        html += `<div class="section-label">No technologies detected via fingerprinting</div>`;
    }

    // Cookies
    if (data.cookies && data.cookies.length > 0) {
        html += `<div class="section-label">Cookies (${data.cookies.length})</div>`;
        html += '<table class="data-table"><thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead><tbody>';
        for (const c of data.cookies) {
            html += `<tr>
                <td style="color:var(--text-primary)">${escapeHTML(c.name)}</td>
                <td class="${c.secure ? 'status-present' : 'status-missing'}">${c.secure ? '✅' : '❌'}</td>
                <td class="${c.httponly ? 'status-present' : 'status-missing'}">${c.httponly ? '✅' : '❌'}</td>
                <td class="${c.samesite ? 'status-present' : 'status-missing'}">${c.samesite ? '✅' : '❌'}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    // Issues
    if (data.issues && data.issues.length > 0) {
        html += `<div class="section-label">Security Findings</div>`;
        html += renderFindings(data.issues);
    }

    body.innerHTML = html;
}

function renderVulnResults(body, data) {
    let html = '';

    // Summary stats
    const summary = data.summary || {};
    html += `
        <div class="stats-row">
            <div class="stat-box">
                <div class="stat-value" style="color:var(--cyan)">${summary.total_checks || 0}</div>
                <div class="stat-label">Checks Run</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:${summary.vulnerabilities_found > 0 ? 'var(--red)' : 'var(--green)'}">${summary.vulnerabilities_found || 0}</div>
                <div class="stat-label">Vulns Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--red)">${summary.high || 0}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--amber)">${summary.medium || 0}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--blue)">${summary.low || 0}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
    `;

    // Vulnerabilities
    if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        html += `<div class="section-label">Vulnerabilities Detected</div>`;
        for (const vuln of data.vulnerabilities) {
            html += `<div class="finding severity-${vuln.severity}">
                <div class="finding-header">
                    <span class="finding-title">${escapeHTML(vuln.title)}</span>
                    <span class="finding-severity">${vuln.severity}</span>
                </div>
                <div class="finding-detail">${escapeHTML(vuln.detail)}</div>
                ${vuln.category ? `<div class="finding-category">${escapeHTML(vuln.category)}</div>` : ''}
                ${vuln.remediation ? `<div class="finding-remediation">${escapeHTML(vuln.remediation)}</div>` : ''}
            </div>`;
        }
    } else {
        html += `<div class="section-label" style="color:var(--green)">✅ No vulnerabilities detected</div>`;
    }

    body.innerHTML = html;
}

function renderReconResults(body, data) {
    let html = '';

    // Summary stats
    const foundCount = (data.found || []).length;
    const forbiddenCount = (data.forbidden || []).length;
    const infoCount = (data.info_files || []).length;

    html += `
        <div class="stats-row">
            <div class="stat-box">
                <div class="stat-value" style="color:var(--cyan)">${data.total_checked || 0}</div>
                <div class="stat-label">Paths Checked</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:${foundCount > 0 ? 'var(--red)' : 'var(--green)'}">${foundCount}</div>
                <div class="stat-label">Exposed Files</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--amber)">${forbiddenCount}</div>
                <div class="stat-label">Forbidden (403)</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--blue)">${infoCount}</div>
                <div class="stat-label">Info Files</div>
            </div>
        </div>
    `;

    // Exposed files
    if (data.found && data.found.length > 0) {
        html += `<div class="section-label">⚠️ Exposed Sensitive Files (${data.found.length})</div>`;
        html += '<table class="data-table"><thead><tr><th>Path</th><th>Category</th><th>Status</th><th>Severity</th></tr></thead><tbody>';
        for (const f of data.found) {
            html += `<tr>
                <td style="color:var(--text-primary);font-weight:500;font-family:var(--font-mono)">${escapeHTML(f.path)}</td>
                <td>${escapeHTML(f.category)}</td>
                <td>${f.status}</td>
                <td><span class="finding-severity">${f.severity}</span></td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    // Forbidden files
    if (data.forbidden && data.forbidden.length > 0) {
        html += `<div class="section-label">🔒 Forbidden Paths (${data.forbidden.length})</div>`;
        html += '<table class="data-table"><thead><tr><th>Path</th><th>Category</th><th>Note</th></tr></thead><tbody>';
        for (const f of data.forbidden) {
            html += `<tr>
                <td style="color:var(--text-primary);font-family:var(--font-mono)">${escapeHTML(f.path)}</td>
                <td>${escapeHTML(f.category)}</td>
                <td>${escapeHTML(f.note || '')}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    // Info files  
    if (data.info_files && data.info_files.length > 0) {
        html += `<div class="section-label">ℹ️ Security Files Found</div>`;
        for (const f of data.info_files) {
            html += `<div class="finding severity-info">
                <div class="finding-header">
                    <span class="finding-title">${escapeHTML(f.path)}</span>
                    <span class="finding-severity">info</span>
                </div>
                <div class="finding-detail">${escapeHTML(f.description)}</div>
            </div>`;
        }
    }

    // Robots.txt disallowed paths
    if (data.robots_disallowed && data.robots_disallowed.length > 0) {
        html += `<div class="section-label">🤖 Robots.txt Disallowed Paths</div>`;
        html += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
        for (const path of data.robots_disallowed) {
            html += `<span class="tag">${escapeHTML(path)}</span>`;
        }
        html += '</div>';
    }

    // Issues
    if (data.issues && data.issues.length > 0) {
        html += `<div class="section-label">Findings</div>`;
        html += renderFindings(data.issues);
    }

    if (foundCount === 0 && forbiddenCount === 0) {
        html += `<div class="section-label" style="color:var(--green)">✅ No sensitive files exposed</div>`;
    }

    body.innerHTML = html;
}

function renderWAFResults(body, data) {
    let html = '';

    // WAF/CDN Detection Status
    const wafProducts = data.waf_products || [];
    const cdnProducts = data.cdn_products || [];

    html += `
        <div class="stats-row">
            <div class="stat-box">
                <div class="stat-value" style="color:${data.waf_detected ? 'var(--green)' : 'var(--amber)'}">${data.waf_detected ? 'YES' : 'NO'}</div>
                <div class="stat-label">WAF Detected</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:${data.cdn_detected ? 'var(--green)' : 'var(--text-secondary)'}">${data.cdn_detected ? 'YES' : 'NO'}</div>
                <div class="stat-label">CDN Detected</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--cyan)">${wafProducts.length + cdnProducts.length}</div>
                <div class="stat-label">Products Found</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" style="color:var(--blue)">${(data.protection_headers || []).length}</div>
                <div class="stat-label">Protection Headers</div>
            </div>
        </div>
    `;

    // WAF Products
    if (wafProducts.length > 0) {
        html += `<div class="section-label">🛡️ WAF / Security Products</div>`;
        for (const p of wafProducts) {
            html += `<div class="finding severity-info">
                <div class="finding-header">
                    <span class="finding-title">${escapeHTML(p.name)}</span>
                    <span class="finding-severity">${escapeHTML(p.type)}</span>
                </div>
                <div class="finding-detail">Evidence: ${escapeHTML(p.evidence)}</div>
            </div>`;
        }
    }

    // CDN Products
    if (cdnProducts.length > 0) {
        html += `<div class="section-label">🌐 CDN / Edge Services</div>`;
        for (const p of cdnProducts) {
            html += `<div class="finding severity-info">
                <div class="finding-header">
                    <span class="finding-title">${escapeHTML(p.name)}</span>
                    <span class="finding-severity">CDN</span>
                </div>
                <div class="finding-detail">Evidence: ${escapeHTML(p.evidence)}</div>
            </div>`;
        }
    }

    // Protection Headers
    if (data.protection_headers && data.protection_headers.length > 0) {
        html += `<div class="section-label">🔐 Protection Headers</div>`;
        html += '<table class="data-table"><thead><tr><th>Header</th><th>Value</th><th>Purpose</th></tr></thead><tbody>';
        for (const h of data.protection_headers) {
            html += `<tr>
                <td style="color:var(--text-primary);font-weight:500">${escapeHTML(h.header)}</td>
                <td style="font-family:var(--font-mono);font-size:0.75rem">${escapeHTML(h.value)}</td>
                <td>${escapeHTML(h.description)}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    // Issues / Assessment
    if (data.issues && data.issues.length > 0) {
        html += `<div class="section-label">Assessment</div>`;
        html += renderFindings(data.issues);
    }

    body.innerHTML = html;
}

// ── Helpers ──

function renderFindings(findings) {
    return findings.map(f => `
        <div class="finding severity-${f.severity}">
            <div class="finding-header">
                <span class="finding-title">${escapeHTML(f.title)}</span>
                <span class="finding-severity">${f.severity}</span>
            </div>
            <div class="finding-detail">${escapeHTML(f.detail)}</div>
            ${f.remediation ? `<div class="finding-remediation">${escapeHTML(f.remediation)}</div>` : ''}
        </div>
    `).join('');
}

function getGradeColor(grade) {
    const colors = { 'A+': '#00ff88', 'A': '#00ff88', 'B': '#00ffcc', 'C': '#ffaa00', 'D': '#ff4466', 'F': '#ff4466' };
    return colors[grade] || '#8b95a5';
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function escapeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function shakeElement(el) {
    el.style.animation = 'none';
    el.offsetHeight; // Trigger reflow
    el.style.animation = 'shake 0.5s ease';
    setTimeout(() => { el.style.animation = ''; }, 500);
}

// Enter key support
document.addEventListener('DOMContentLoaded', () => {
    initMatrix();

    document.getElementById('target-input').addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            startScan();
        }
    });
});

// Add shake animation
const shakeStyle = document.createElement('style');
shakeStyle.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        10%, 30%, 50%, 70%, 90% { transform: translateX(-4px); }
        20%, 40%, 60%, 80% { transform: translateX(4px); }
    }
`;
document.head.appendChild(shakeStyle);
