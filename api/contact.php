<?php
/**
 * Tecfuge Markets — Production Enquiry Form API
 * Endpoint: POST /api/contact.php
 * Compatible with Hostinger Shared Hosting (PHP 8.0+) & Microsoft Graph API (Exchange Online)
 */

declare(strict_types=1);

// Prevent PHP warnings/notices from corrupting JSON output
ini_set('display_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

// Handle preflight OPTIONS safely
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Accept');
    http_response_code(204);
    exit;
}

// 1. Reject unsupported HTTP methods
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode([
        'ok' => false,
        'error' => 'Method not allowed. Only POST requests are accepted.',
    ]);
    exit;
}

// 2. Enforce request size limit (Max 32 KB)
$maxBytes = 32768;
$contentLength = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
if ($contentLength > $maxBytes) {
    http_response_code(413);
    echo json_encode([
        'ok' => false,
        'error' => "We couldn't submit your enquiry right now. Please try again or contact us directly at markets@tecfuge.com.",
    ]);
    exit;
}

$rawBody = file_get_contents('php://input', false, null, 0, $maxBytes + 1);
if ($rawBody === false || strlen($rawBody) === 0 || strlen($rawBody) > $maxBytes) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => "We couldn't submit your enquiry right now. Please try again or contact us directly at markets@tecfuge.com.",
    ]);
    exit;
}

$payload = json_decode($rawBody, true);
if (!is_array($payload)) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => 'Invalid request payload.',
    ]);
    exit;
}

// 3. Honeypot spam protection
if (!empty($payload['_gotcha'])) {
    // Silently reject automated bot submissions
    http_response_code(200);
    echo json_encode([
        'ok' => true,
        'message' => 'Thank you for contacting Tecfuge Markets. Your enquiry has been received successfully. Our team will get back to you shortly.',
    ]);
    exit;
}

// 4. Lightweight IP-based rate limiting (Max 5 requests per 10 minutes per IP)
$clientIp = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$ipHash = hash('sha256', 'tecfuge_rl_' . $clientIp);
$rateLimitFile = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'tf_rl_' . substr($ipHash, 0, 24) . '.json';
$now = time();
$windowSeconds = 600;
$maxRequests = 5;

$timestamps = [];
if (is_file($rateLimitFile)) {
    $rawRateData = @file_get_contents($rateLimitFile);
    if ($rawRateData !== false) {
        $decoded = json_decode($rawRateData, true);
        if (is_array($decoded)) {
            foreach ($decoded as $ts) {
                if (is_int($ts) && ($now - $ts) < $windowSeconds) {
                    $timestamps[] = $ts;
                }
            }
        }
    }
}

if (count($timestamps) >= $maxRequests) {
    http_response_code(429);
    echo json_encode([
        'ok' => false,
        'error' => 'Too many enquiries submitted recently. Please wait a few minutes or email us directly at markets@tecfuge.com.',
    ]);
    exit;
}

$timestamps[] = $now;
@file_put_contents($rateLimitFile, json_encode($timestamps), LOCK_EX);

// 5. Sanitize helper functions
function cleanLine(mixed $val, int $maxLength = 250): string {
    if (!is_string($val) && !is_numeric($val)) {
        return '';
    }
    $str = trim((string) $val);
    // Strip control characters and CRLF to prevent header injection
    $str = preg_replace('/[\r\n\t\x00-\x1F\x7F]+/u', ' ', $str) ?? '';
    return mb_substr($str, 0, $maxLength, 'UTF-8');
}

function cleanMultiline(mixed $val, int $maxLength = 3000): string {
    if (!is_string($val) && !is_numeric($val)) {
        return '';
    }
    $str = trim((string) $val);
    $str = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/u', '', $str) ?? '';
    return mb_substr($str, 0, $maxLength, 'UTF-8');
}

function escapeHtml(string $val): string {
    return htmlspecialchars($val, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// 6. Extract and validate required fields
$formSource         = cleanLine($payload['formSource'] ?? 'Main Contact Form', 100);
$fullName           = cleanLine($payload['fullName'] ?? '', 140);
$email              = cleanLine($payload['email'] ?? '', 180);
$phone              = cleanLine($payload['phone'] ?? '', 50);
$company            = cleanLine($payload['company'] ?? '', 180);
$status             = cleanLine($payload['status'] ?? '', 120);
$selectedPackage    = cleanLine($payload['selectedPackage'] ?? '', 120);
$industry           = cleanLine($payload['industry'] ?? '', 120);
$country            = cleanLine($payload['country'] ?? '', 120);
$websiteUrl         = cleanLine($payload['websiteUrl'] ?? '', 250);
$amazonStatus       = cleanLine($payload['amazonAccountStatus'] ?? '', 80);
$amazonStoreUrl     = cleanLine($payload['amazonStoreUrl'] ?? '', 250);
$preferredSlot      = cleanLine($payload['preferredSlot'] ?? '', 140);
$message            = cleanMultiline($payload['message'] ?? '', 3000);

$marketplaces = [];
if (isset($payload['marketplaces']) && is_array($payload['marketplaces'])) {
    foreach ($payload['marketplaces'] as $mp) {
        $cleanedMp = cleanLine($mp, 60);
        if ($cleanedMp !== '') {
            $marketplaces[] = $cleanedMp;
        }
    }
}
$marketplacesText = count($marketplaces) > 0 ? implode(', ', $marketplaces) : 'Not specified';

// Validate mandatory fields
if ($fullName === '' || $email === '' || $phone === '') {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => 'Please complete your full name, business email, and phone/WhatsApp number.',
    ]);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => 'Please enter a valid business email address.',
    ]);
    exit;
}

$phoneDigits = preg_replace('/\D+/', '', $phone) ?? '';
if (strlen($phoneDigits) < 7 || strlen($phoneDigits) > 16) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => 'Please enter a valid phone or WhatsApp number.',
    ]);
    exit;
}

if ($company === '') {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => 'Please enter your company or brand name.',
    ]);
    exit;
}

if (count($marketplaces) === 0) {
    http_response_code(400);
    echo json_encode([
        'ok' => false,
        'error' => 'Please select at least one target marketplace.',
    ]);
    exit;
}

// 7. Load Secure Microsoft 365 Configuration (Strictly outside public_html first, then environment variables)
$config = [];
$candidateConfigPaths = [];

$explicitConfigPath = getenv('TECFUGE_MAIL_CONFIG_PATH');
if (is_string($explicitConfigPath) && trim($explicitConfigPath) !== '') {
    $candidateConfigPaths[] = trim($explicitConfigPath);
}

if (!empty($_SERVER['DOCUMENT_ROOT']) && is_string($_SERVER['DOCUMENT_ROOT'])) {
    $docRootParent = dirname(rtrim($_SERVER['DOCUMENT_ROOT'], '/\\'));
    if ($docRootParent !== '' && $docRootParent !== '.' && $docRootParent !== '/') {
        $candidateConfigPaths[] = $docRootParent . '/config/mail-config.php';
    }
}

// Support both standalone subdomain roots and nested subdomain roots on Hostinger shared hosting:
// - Standalone subdomain root (e.g. .../domains/markets.tecfuge.com/public_html/api) -> dirname(__DIR__, 2)
// - Nested subdomain root (e.g. .../domains/tecfuge.com/public_html/markets/api)    -> dirname(__DIR__, 3)
// - Account home root (e.g. <account-home>/config/mail-config.php)                   -> dirname(__DIR__, 3) or dirname(__DIR__, 4)
$candidateConfigPaths[] = dirname(__DIR__, 2) . '/config/mail-config.php';
$candidateConfigPaths[] = dirname(__DIR__, 3) . '/config/mail-config.php';
$candidateConfigPaths[] = dirname(__DIR__, 4) . '/config/mail-config.php';

foreach (array_unique($candidateConfigPaths) as $path) {
    $normalizedPath = str_replace('\\', '/', $path);
    // Never load a configuration file situated inside any public_html web root
    if (str_contains($normalizedPath, '/public_html/')) {
        continue;
    }
    if (is_file($path) && is_readable($path)) {
        $loaded = include $path;
        if (is_array($loaded)) {
            $config = $loaded;
            break;
        }
    }
}

$getConfigValue = static function (string $key, string $default = '') use ($config): string {
    if (!empty($config[$key]) && is_string($config[$key])) {
        return trim($config[$key]);
    }
    $envVal = getenv($key);
    if (is_string($envVal) && trim($envVal) !== '') {
        return trim($envVal);
    }
    if (!empty($_ENV[$key]) && is_string($_ENV[$key])) {
        return trim($_ENV[$key]);
    }
    if (!empty($_SERVER[$key]) && is_string($_SERVER[$key])) {
        return trim($_SERVER[$key]);
    }
    return $default;
};

$tenantId          = $getConfigValue('MS_TENANT_ID');
$clientId          = $getConfigValue('MS_CLIENT_ID');
$clientSecret      = $getConfigValue('MS_CLIENT_SECRET');
$senderEmail       = $getConfigValue('MS_SENDER_EMAIL', 'markets@tecfuge.com');
$notificationEmail = $getConfigValue('NOTIFICATION_EMAIL', 'markets@tecfuge.com');

if (
    $tenantId === '' ||
    $clientId === '' ||
    $clientSecret === '' ||
    str_starts_with($tenantId, 'YOUR_') ||
    str_starts_with($clientId, 'YOUR_') ||
    str_starts_with($clientSecret, 'YOUR_')
) {
    error_log('[Tecfuge Markets Mail API] Microsoft Graph credentials are not configured on the server.');
    http_response_code(503);
    echo json_encode([
        'ok' => false,
        'error' => "We couldn't submit your enquiry right now. Please try again or contact us directly at markets@tecfuge.com.",
    ]);
    exit;
}

// 8. Build Subject & Branded HTML Notification Email
$dubaiTz = new DateTimeZone('Asia/Dubai');
$utcTz   = new DateTimeZone('UTC');
$nowDubai = (new DateTimeImmutable('now', $dubaiTz))->format('d M Y, h:i A \G\M\T+4');
$nowUtc   = (new DateTimeImmutable('now', $utcTz))->format('Y-m-d H:i:s \U\T\C');

if ($selectedPackage !== '') {
    $emailSubject = "New Package Enquiry | {$selectedPackage} | Tecfuge Markets";
    $headingTitle = "New Package Enquiry — {$selectedPackage}";
} else {
    $emailSubject = "New Website Enquiry | Tecfuge Markets | {$fullName}";
    $headingTitle = "New Website Enquiry";
}

$rows = [
    'Form Source'        => $formSource,
    'Customer Name'      => $fullName,
    'Work / Business Email' => $email,
    'Phone / WhatsApp'   => $phone,
    'Company / Brand'    => $company !== '' ? $company : 'Not specified',
];

if ($selectedPackage !== '') {
    $rows['Selected Package'] = $selectedPackage;
}
if ($status !== '') {
    $statusLabels = [
        'new-entry'    => 'New to UAE Market',
        'active-scale' => 'Selling & Want to Scale',
        'fix-perf'     => 'Fixing Ad / Catalog Issues',
    ];
    $rows['Marketplace Status'] = $statusLabels[$status] ?? $status;
}
if ($marketplacesText !== 'Not specified') {
    $rows['Selected Marketplaces'] = $marketplacesText;
}
if ($industry !== '') {
    $rows['Industry / Category'] = $industry;
}
if ($country !== '') {
    $rows['Country / Target Market'] = $country;
}
if ($websiteUrl !== '') {
    $rows['Website URL'] = $websiteUrl;
}
if ($amazonStatus !== '') {
    $amazonLabels = [
        'yes'    => 'Yes (Active Seller Account)',
        'no'     => 'No (Needs Account Setup)',
        'unsure' => 'Unsure / Needs Guidance',
    ];
    $rows['Amazon Seller Account'] = $amazonLabels[$amazonStatus] ?? $amazonStatus;
}
if ($amazonStoreUrl !== '') {
    $rows['Amazon Store Link'] = $amazonStoreUrl;
}
if ($preferredSlot !== '') {
    $rows['Preferred Session Slot'] = $preferredSlot;
}
$rows['Submission Time (UAE)'] = $nowDubai;
$rows['Submission Time (UTC)'] = $nowUtc;

$tableRowsHtml = '';
foreach ($rows as $label => $value) {
    $safeLabel = escapeHtml($label);
    $safeValue = escapeHtml($value);
    $tableRowsHtml .= "
      <tr>
        <td style=\"padding:10px 14px;border-bottom:1px solid #E2E8F0;font-weight:700;color:#334155;width:36%;font-size:13px;background-color:#F8FAF9;\">{$safeLabel}</td>
        <td style=\"padding:10px 14px;border-bottom:1px solid #E2E8F0;color:#0F172A;font-size:13px;\">{$safeValue}</td>
      </tr>";
}

$safeHeading = escapeHtml($headingTitle);
$safeMessage = nl2br(escapeHtml($message !== '' ? $message : 'No additional message provided.'));
$safeReplyEmail = escapeHtml($email);
$safeFullName = escapeHtml($fullName);

$htmlBody = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{$safeHeading}</title>
</head>
<body style="margin:0;padding:24px;background-color:#F4F7F5;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#0F172A;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:640px;margin:0 auto;background-color:#FFFFFF;border-radius:16px;overflow:hidden;border:1px solid #E2E8F0;">
    <tr>
      <td style="padding:24px 28px;background-color:#1E6B47;color:#FFFFFF;">
        <div style="font-size:11px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:#F2BA2D;">TECFUGE MARKETS · TRULY TRANSFORM</div>
        <h1 style="margin:6px 0 0 0;font-size:20px;font-weight:800;color:#FFFFFF;">{$safeHeading}</h1>
      </td>
    </tr>
    <tr>
      <td style="padding:24px 28px;">
        <p style="margin:0 0 16px 0;font-size:14px;color:#475569;line-height:1.5;">
          A new website enquiry has been submitted by <strong>{$safeFullName}</strong> (<a href="mailto:{$safeReplyEmail}" style="color:#1E6B47;text-decoration:none;font-weight:600;">{$safeReplyEmail}</a>). You can reply directly to this email to respond to the customer.
        </p>

        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse;border:1px solid #E2E8F0;border-radius:8px;overflow:hidden;">
          {$tableRowsHtml}
        </table>

        <div style="margin-top:20px;padding:16px;background-color:#F8FAF9;border:1px solid #E2E8F0;border-radius:10px;">
          <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.8px;color:#1E6B47;margin-bottom:8px;">
            Customer Message / Business Requirements
          </div>
          <div style="font-size:13px;color:#1E293B;line-height:1.6;">
            {$safeMessage}
          </div>
        </div>
      </td>
    </tr>
    <tr>
      <td style="padding:16px 28px;background-color:#F1F5F3;border-top:1px solid #E2E8F0;font-size:11px;color:#64748B;">
        Delivered automatically via Tecfuge Markets Website Enquiry Service · Official Mailbox: markets@tecfuge.com
      </td>
    </tr>
  </table>
</body>
</html>
HTML;

// 9. Acquire OAuth 2.0 Access Token from Microsoft Entra ID (Client Credentials Flow)
$tokenUrl = 'https://login.microsoftonline.com/' . rawurlencode($tenantId) . '/oauth2/v2.0/token';
$tokenPostFields = http_build_query([
    'client_id'     => $clientId,
    'client_secret' => $clientSecret,
    'scope'         => 'https://graph.microsoft.com/.default',
    'grant_type'    => 'client_credentials',
]);

$chToken = curl_init($tokenUrl);
curl_setopt_array($chToken, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $tokenPostFields,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_CONNECTTIMEOUT => 8,
    CURLOPT_SSL_VERIFYPEER => true,
]);

$tokenResponseRaw = curl_exec($chToken);
$tokenHttpCode    = (int) curl_getinfo($chToken, CURLINFO_HTTP_CODE);
$tokenCurlErr     = curl_error($chToken);
curl_close($chToken);

if ($tokenResponseRaw === false || $tokenHttpCode !== 200) {
    $oauthErrCode = 'unknown';
    if (is_string($tokenResponseRaw) && $tokenResponseRaw !== '') {
        $decodedErr = json_decode($tokenResponseRaw, true);
        if (is_array($decodedErr) && !empty($decodedErr['error']) && is_string($decodedErr['error'])) {
            $oauthErrCode = $decodedErr['error'];
        }
    }
    error_log('[Tecfuge Markets Mail API] OAuth token request failed. HTTP Code: ' . $tokenHttpCode . ' OAuth Error: ' . $oauthErrCode . ' cURL Error: ' . $tokenCurlErr);
    http_response_code(502);
    echo json_encode([
        'ok' => false,
        'error' => "We couldn't submit your enquiry right now. Please try again or contact us directly at markets@tecfuge.com.",
    ]);
    exit;
}

$tokenData = json_decode($tokenResponseRaw, true);
$accessToken = is_array($tokenData) && !empty($tokenData['access_token']) ? (string) $tokenData['access_token'] : '';

if ($accessToken === '') {
    error_log('[Tecfuge Markets Mail API] OAuth token response did not contain an access_token.');
    http_response_code(502);
    echo json_encode([
        'ok' => false,
        'error' => "We couldn't submit your enquiry right now. Please try again or contact us directly at markets@tecfuge.com.",
    ]);
    exit;
}

// 10. Send Email via Microsoft Graph API (/v1.0/users/{MS_SENDER_EMAIL}/sendMail)
$graphUrl = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($senderEmail) . '/sendMail';
$graphPayload = [
    'message' => [
        'subject' => $emailSubject,
        'body' => [
            'contentType' => 'HTML',
            'content'     => $htmlBody,
        ],
        'toRecipients' => [
            [
                'emailAddress' => [
                    'address' => $notificationEmail,
                ],
            ],
        ],
        'replyTo' => [
            [
                'emailAddress' => [
                    'name'    => $fullName,
                    'address' => $email,
                ],
            ],
        ],
    ],
    'saveToSentItems' => true,
];

$chGraph = curl_init($graphUrl);
curl_setopt_array($chGraph, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => json_encode($graphPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER     => [
        'Authorization: Bearer ' . $accessToken,
        'Content-Type: application/json',
    ],
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_CONNECTTIMEOUT => 8,
    CURLOPT_SSL_VERIFYPEER => true,
]);

$graphResponseRaw = curl_exec($chGraph);
$graphHttpCode    = (int) curl_getinfo($chGraph, CURLINFO_HTTP_CODE);
$graphCurlErr     = curl_error($chGraph);
curl_close($chGraph);

// Microsoft Graph /sendMail returns HTTP 202 Accepted (with an empty body) when accepted for processing
$isGraphAccepted = ($graphResponseRaw !== false) && ($graphHttpCode === 202 || $graphHttpCode === 200 || $graphHttpCode === 204);

if (!$isGraphAccepted) {
    $graphErrCode = 'unknown';
    if (is_string($graphResponseRaw) && $graphResponseRaw !== '') {
        $decodedGraphErr = json_decode($graphResponseRaw, true);
        if (
            is_array($decodedGraphErr) &&
            isset($decodedGraphErr['error']['code']) &&
            is_string($decodedGraphErr['error']['code'])
        ) {
            $graphErrCode = $decodedGraphErr['error']['code'];
        }
    }
    error_log('[Tecfuge Markets Mail API] Graph sendMail failed. HTTP Code: ' . $graphHttpCode . ' Graph Error Code: ' . $graphErrCode . ' cURL Error: ' . $graphCurlErr);
    http_response_code(502);
    echo json_encode([
        'ok' => false,
        'error' => "We couldn't submit your enquiry right now. Please try again or contact us directly at markets@tecfuge.com.",
    ]);
    exit;
}

http_response_code(200);
echo json_encode([
    'ok'      => true,
    'status'  => 'accepted',
    'message' => 'Thank you for contacting Tecfuge Markets. Your enquiry has been received successfully. Our team will get back to you shortly.',
]);

