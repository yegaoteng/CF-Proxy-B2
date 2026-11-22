//
// CF-Proxy-B2 多桶改造版
// 基于 https://github.com/hoochanlon/CF-Proxy-B2 的 index.js 最小改动：
//   - 保留原有 GET/HEAD、HEAD->GET、range 重试、rclone、ALLOWED_HEADERS、welcome 页全部逻辑
//   - 新增：按 URL 首段（或子域）查表，每个别名用【自己的桶名 / 端点 / 一对 key】签名
//   - 不设 BUCKETS_CONFIG 时，行为与原版完全一致（向后兼容单桶）
//
import { AwsClient } from 'aws4fetch'
import welcomeHtml from './welcome.html' assert { type: 'text' }

const UNSIGNABLE_HEADERS = [
    // These headers appear in the request, but are never passed upstream
    'x-forwarded-proto',
    'x-real-ip',
    // We can't include accept-encoding in the signature because Cloudflare
    // sets the incoming accept-encoding header to "gzip, br", then modifies
    // the outgoing request to set accept-encoding to "gzip".
    'accept-encoding',
    // Conditional headers are not consistently passed upstream
    'if-match',
    'if-modified-since',
    'if-none-match',
    'if-range',
    'if-unmodified-since',
];

const HTTPS_PROTOCOL = "https:";
const HTTPS_PORT = "443";
const RANGE_RETRY_ATTEMPTS = 3;

// Filter out cf-* and any other headers we don't want to include in the signature
function filterHeaders(headers, env) {
    return new Headers(Array.from(headers.entries())
        .filter(pair => !(
            UNSIGNABLE_HEADERS.includes(pair[0])
            || pair[0].startsWith('cf-')
            || ('ALLOWED_HEADERS' in env && !env['ALLOWED_HEADERS'].includes(pair[0]))
        ))
    );
}

function createHeadResponse(response) {
    return new Response(null, {
        headers: response.headers,
        status: response.status,
        statusText: response.statusText
    });
}

function isListBucketRequest(env, path) {
    const pathSegments = path.split('/');
    return (env['BUCKET_NAME'] === "$path" && pathSegments.length < 2)
        || (env['BUCKET_NAME'] !== "$path" && path.length === 0);
}

// 端点容错：模板注释写的是不带协议的 "s3.us-west-001.backblazeb2.com"，
// 但原版 new URL(env.B2_ENDPOINT).hostname 会直接抛错；仓库自带的 wrangler.toml 又带了 https://。
// 这里两种都接受，统一返回纯 hostname。
function normalizeEndpoint(endpoint) {
    const s = String(endpoint || '').trim();
    if (!s) return '';
    if (s.includes('://')) {
        try { return new URL(s).hostname; }
        catch { return s.replace(/^https?:\/\//, '').split('/')[0]; }
    }
    return s.split('/')[0];
}

// 网页 Dashboard 粘贴时常见的多余字符清洗（仅在严格解析失败后兜底，不影响正常路径）
function sanitizeBucketJson(raw) {
    let s = String(raw).replace(/^\uFEFF/, '').trim();       // BOM + 首尾空白
    s = s.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();  // Markdown 代码围栏
    s = s.replace(/,\s*$/, '').trim();                      // 整段末尾孤立的逗号
    s = s.replace(/,(\s*[}\]])/g, '$1');                    // 对象/数组内部末尾多余逗号
    return s;
}

// 从 Secret 读取多桶表（整段 JSON），未配置则返回 null → 走原版单桶路径
// JSON 标准允许任意空白/换行，所以 Dashboard 里原样粘贴带缩进的多行 JSON 完全可用。
function loadBuckets(env) {
    const raw = env['BUCKETS_CONFIG'];
    if (!raw) return null;
    let parsed;
    if (typeof raw !== 'string') {
        parsed = raw;
    } else {
        try {
            parsed = JSON.parse(raw);
        } catch (e1) {
            try {
                parsed = JSON.parse(sanitizeBucketJson(raw));
            } catch (e2) {
                throw new Error(`${e1.message}（已自动尝试清洗 Markdown 围栏 / BOM / 尾逗号；请确认没有注释、多余逗号或从别处复制来的装饰字符）`);
            }
        }
    }
    const out = {};
    for (const [alias, c] of Object.entries(parsed)) {
        const endpoint = normalizeEndpoint(c.endpoint);
        if (!c.bucket || !endpoint) throw new Error(`别名 "${alias}" 缺少 bucket 或 endpoint`);
        out[alias] = {
            alias,
            bucket: String(c.bucket),
            endpoint,
            keyId: String(c.keyId || ''),
            appKey: String(c.appKey || ''),
            isPublic: !!c.isPublic,
            allowedHeaders: c.allowedHeaders || null
        };
    }
    return out;
}

// 脱敏诊断：Cloudflare Dashboard 里看不到 Secret 的值，用这个页面确认它到底有没有生效
function diagnosticText(env, buckets, parseError) {
    const raw = env['BUCKETS_CONFIG'];
    const rawStr = raw == null ? '' : String(raw);
    const first = rawStr.replace(/^\uFEFF/, '').trimStart().slice(0, 1);
    const shape = !rawStr ? '（空）'
        : `${rawStr.length} 字符 / ${rawStr.includes('\n') ? '多行（Dashboard 粘贴正常）' : '单行'} / 首字符 "${first}"${first !== '{' ? ' ← 不是 {，可能粘进了围栏或注释' : ''}`;
    const mode = parseError ? '❌ BUCKETS_CONFIG 解析失败'
        : buckets ? '多桶 (BUCKETS_CONFIG)'
        : (env['B2_ENDPOINT'] ? '单桶兼容' : '❌ 未配置');
    const lines = [
        'CF-Proxy-B2 多桶版 · 配置诊断（不显示任何密钥）',
        '================================================',
        `模式            : ${mode}`,
        `BUCKET_SOURCE   : ${String(env['BUCKET_SOURCE'] || 'path')}`,
        `配置形态        : ${shape}`,
        `BUCKETS_CONFIG  : ${rawStr ? '已设置' : '未设置'}${parseError ? '（解析失败: ' + parseError + '）' : ''}`,
        `B2_ENDPOINT     : ${env['B2_ENDPOINT'] ? '已设置' : '未设置'}`,
        `B2_KEY_ID       : ${env['B2_APPLICATION_KEY_ID'] ? '已设置' : '未设置'}`,
        `B2_APPLICATION_KEY : ${env['B2_APPLICATION_KEY'] ? '已设置(Secret)' : '未设置'}`,
        `BUCKET_NAME     : ${env['BUCKET_NAME'] || '未设置'}`,
        `ALLOW_LIST_BUCKET : ${env['ALLOW_LIST_BUCKET'] || '未设置'}`,
        `RCLONE_DOWNLOAD : ${env['RCLONE_DOWNLOAD'] || '未设置'}`,
        ''
    ];
    if (buckets) {
        lines.push(`已加载别名 (${Object.keys(buckets).length}):`);
        for (const c of Object.values(buckets)) {
            lines.push(`  ${c.alias.padEnd(16)} -> ${c.bucket} @ ${c.endpoint} | key:${c.keyId ? '有' : '无'} | public:${c.isPublic}`);
        }
        lines.push('', '提示: 访问 /<别名>/<文件路径> ，例如 /one/4.jpg');
    } else {
        lines.push('没有加载任何别名。请二选一配置：',
            '  A 多桶: Dashboard → Settings → Variables and Secrets → Add → 类型 Secret',
            '          变量名 BUCKETS_CONFIG，Value 原样粘贴整段 JSON（带缩进的多行也可以）→ Deploy',
            '          或 CLI: jq -c . buckets.json | npx wrangler secret put BUCKETS_CONFIG',
            '  B 单桶: [vars] 里打开 B2_ENDPOINT / B2_APPLICATION_KEY_ID / BUCKET_NAME + Secret B2_APPLICATION_KEY',
            '',
            '  注意变量名是 BUCKETS_CONFIG，不是 CONFIG / BUCKETS / B2_CONFIG。');
    }
    return lines.join('\n');
}

function configHint(env) {
    return [
        'CF-Proxy-B2 多桶版：配置缺失，当前请求没有命中任何可用模式。',
        '',
        '【为什么看到这句】',
        '  既没有有效的 BUCKETS_CONFIG（多桶模式），也没有 B2_ENDPOINT + BUCKET_NAME（单桶兼容模式）。',
        '  注意：如果只覆盖了 wrangler.toml 而没设 Secret，就会卡在这里；',
        '  如果 index.js 仍是仓库原版而 wrangler.toml 换成多桶版，原版 new URL(undefined) 会抛 Error 1101。',
        '',
        '【两种模式二选一，必须配齐其一】',
        '',
        'A. 多桶模式（推荐，可全程网页操作，不用指令）',
        '   Dashboard → Workers & Pages → 你的 Worker → Settings → Variables and Secrets → Add',
        '     类型  : Secret（加密），不要选 Plaintext / 不要加进 [vars]',
        '     变量名: BUCKETS_CONFIG   ← 不是 CONFIG / BUCKETS / B2_CONFIG',
        '     Value : 直接原样粘贴整段 JSON，带缩进的多行完全可以，不用压成单行',
        '   然后 Save → Deploy（Secret 变更会生成新版本，不部署不生效）。',
        '   CLI 等价写法（可选）：jq -c . buckets.json | npx wrangler secret put BUCKETS_CONFIG',
        '   然后访问 /one/4.jpg（URL 首段是别名，不是真实桶名）。',
        '',
        'B. 单桶兼容模式',
        '   在 wrangler.toml 的 [vars] 取消注释这三项：',
        '     B2_ENDPOINT = "https://s3.us-east-005.backblazeb2.com"   ← 必须带 https://',
        '     B2_APPLICATION_KEY_ID = "<key id>"',
        '     BUCKET_NAME = "$path"',
        '   并设 Secret：npx wrangler secret put B2_APPLICATION_KEY',
        '',
        '【自查】访问 /__diag 查看当前实际生效的模式与别名（不显示密钥）。',
        '【常见 1101】端点按模板注释写成不带协议的 s3.us-west-001.backblazeb2.com，原版 new URL() 会抛错。'
    ].join('\n');
}

export default {
    async fetch(request, env) {
        if (!['GET', 'HEAD'].includes(request.method)) {
            return new Response(null, { status: 405, statusText: "Method Not Allowed" });
        }

        const url = new URL(request.url);
        url.protocol = HTTPS_PROTOCOL;
        url.port = HTTPS_PORT;

        let path = url.pathname.replace(/^\//, '');
        path = path.replace(/\/$/, '');

        // ---------- 多桶解析 ----------
        let buckets = null;
        let parseError = null;
        try {
            buckets = loadBuckets(env);
        } catch (e) {
            parseError = e.message;
        }

        // 脱敏诊断页：直接访问 /__diag 就能确认 Secret 有没有生效
        if (path === '__diag') {
            return new Response(diagnosticText(env, buckets, parseError), {
                headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-store' },
                status: 200
            });
        }
        if (parseError) {
            return new Response('BUCKETS_CONFIG 配置错误: ' + parseError + '\n\n访问 /__diag 查看详情。', {
                headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-store' },
                status: 500
            });
        }

        const source = String(env['BUCKET_SOURCE'] || 'path').toLowerCase(); // path | host
        let cfg = null;
        let effectiveEnv = env;   // 单桶兼容：原样

        if (buckets) {
            const alias = source === 'host'
                ? url.hostname.split('.')[0]
                : (path.split('/').filter(Boolean)[0] || '');
            cfg = buckets[alias] || null;
            if (!cfg) return new Response('Unknown bucket alias', { status: 404 });

            // 只构造 filterHeaders / isListBucketRequest / rclone 用到的键，不展开 env（bindings 未必可枚举）
            effectiveEnv = {
                BUCKET_NAME: source === 'host' ? '$host' : '$path',
                B2_ENDPOINT: 'https://' + cfg.endpoint,
                ALLOW_LIST_BUCKET: String(env['ALLOW_LIST_BUCKET']),
                RCLONE_DOWNLOAD: String(env['RCLONE_DOWNLOAD'])
            };
            const ah = cfg.allowedHeaders || env['ALLOWED_HEADERS'];
            if (ah) effectiveEnv.ALLOWED_HEADERS = ah;
        }

        const b2Hostname = normalizeEndpoint(effectiveEnv['B2_ENDPOINT']);
        // 兼容模式还必须有 BUCKET_NAME，否则 switch 会走 default 拼出 "undefined.xxx"
        if (!b2Hostname || (!buckets && !effectiveEnv['BUCKET_NAME'])) {
            return new Response(configHint(env), {
                headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'no-store' },
                status: 500
            });
        }

        // ---------- 列桶保护 / 欢迎页 ----------
        if (isListBucketRequest(effectiveEnv, path) && String(effectiveEnv['ALLOW_LIST_BUCKET']) !== "true") {
            const html = welcomeHtml
                .replace('{{BUCKET_NAME}}', cfg ? cfg.alias : effectiveEnv['BUCKET_NAME'])
                .replace('{{B2_ENDPOINT}}', cfg ? cfg.endpoint : b2Hostname);
            return new Response(html, {
                headers: { 'Content-Type': 'text/html;charset=utf-8' },
                status: 200
            });
        }

        const rcloneDownload = String(effectiveEnv["RCLONE_DOWNLOAD"]) === 'true';

        // ---------- 上游 URL 拼接 ----------
        // 关键：多桶时用 cfg.bucket（真实桶名）而不是 URL 里的别名，且用 cfg.endpoint（可跨区域）
        const upstreamHost = cfg ? cfg.endpoint : b2Hostname;
        let bucketName;
        switch (effectiveEnv['BUCKET_NAME']) {
            case "$path": {
                const pathSegments = path.split('/').filter(segment => segment.length > 0);
                if (pathSegments.length === 0) {
                    return new Response("Bucket name required in path", { status: 400 });
                }
                bucketName = cfg ? cfg.bucket : pathSegments[0];
                const remainingPath = pathSegments.slice(1).join('/');
                url.hostname = bucketName + "." + upstreamHost;
                url.pathname = remainingPath ? '/' + remainingPath : '/';
                break;
            }
            case "$host": {
                bucketName = cfg ? cfg.bucket : url.hostname.split('.')[0];
                url.hostname = bucketName + '.' + upstreamHost;
                url.pathname = '/' + path;
                break;
            }
            default: {
                bucketName = cfg ? cfg.bucket : effectiveEnv['BUCKET_NAME'];
                url.hostname = bucketName + "." + upstreamHost;
                url.pathname = '/' + path;
            }
        }

        const headers = filterHeaders(request.headers, effectiveEnv);

        // ---------- rclone 路径改写（必须在签名之前，签的是改写后的 URL）----------
        if (rcloneDownload) {
            if (effectiveEnv['BUCKET_NAME'] === "$path") {
                url.pathname = url.pathname.replace(/^\/file\//, "/");
            } else {
                url.pathname = url.pathname.replace(/^\/file\/[^/]+\//, "/");
            }
        }

        // ---------- 签名（按请求构造，天然支持不同 key）----------
        // 注意：aws4fetch 的 region 不要乱传，原版就没传，B2 S3 兼容端点不校验 region。
        // HEAD 会被 Cloudflare 改成 GET 导致签名失效，统一按 GET 签名。
        let signedRequest;
        if (cfg && cfg.isPublic && !cfg.keyId) {
            // 公开桶且没配 key：不加 Authorization，直接回源（CF 也会正常缓存）
            signedRequest = new Request(url.toString(), { method: 'GET', headers });
        } else {
            const client = new AwsClient({
                "accessKeyId": cfg ? cfg.keyId : effectiveEnv['B2_APPLICATION_KEY_ID'],
                "secretAccessKey": cfg ? cfg.appKey : effectiveEnv['B2_APPLICATION_KEY'],
                "service": "s3",
            });
            signedRequest = await client.sign(url.toString(), { method: 'GET', headers });
        }

        const requestMethod = request.method;

        // ---------- range 重试（原逻辑保留）----------
        if (signedRequest.headers.has("range")) {
            let attempts = RANGE_RETRY_ATTEMPTS;
            let response;
            do {
                const controller = new AbortController();
                response = await fetch(signedRequest.url, {
                    method: signedRequest.method,
                    headers: signedRequest.headers,
                    signal: controller.signal,
                });
                if (response.headers.has("content-range")) {
                    if (attempts < RANGE_RETRY_ATTEMPTS) {
                        console.log(`Retry for ${signedRequest.url} succeeded - response has content-range header`);
                    }
                    break;
                } else if (response.ok) {
                    attempts -= 1;
                    console.error(`Range header in request for ${signedRequest.url} but no content-range header in response. Will retry ${attempts} more times`);
                    if (attempts > 0) controller.abort();
                } else {
                    break;
                }
            } while (attempts > 0);

            if (attempts <= 0) {
                console.error(`Tried range request for ${signedRequest.url} ${RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`);
            }
            if (requestMethod === 'HEAD') return createHeadResponse(response);
            return response;
        }

        const fetchPromise = fetch(signedRequest);
        if (requestMethod === 'HEAD') {
            const response = await fetchPromise;
            return createHeadResponse(response);
        }
        return fetchPromise;
    },
};
