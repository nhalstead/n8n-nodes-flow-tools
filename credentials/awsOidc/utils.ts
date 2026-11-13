import { sign } from 'aws4';
import type { Request as Aws4Request } from 'aws4';
import type { IDataObject, IHttpRequestOptions } from 'n8n-workflow';
import { UserError } from 'n8n-workflow';

export type AwsOidcCredentials = {
	region: string;
	accessTokenUrl: string;
	clientId: string;
	clientSecret: string;
	scope?: string;
	/** OAuth2 `audience` body param (Auth0 / Authentik / many IdPs). Shapes JWT `aud`. */
	audience?: string;
	/** OAuth2 `resource` body param (RFC 8707). Some IdPs prefer this over `audience`. */
	resource?: string;
	authentication: 'header' | 'body';
	tokenProperty: 'access_token' | 'id_token';
	roleArn: string;
	roleSessionName: string;
	durationSeconds?: number;
};

export type AwsTemporaryCredentials = {
	accessKeyId: string;
	secretAccessKey: string;
	sessionToken: string;
};

function trimString(value: unknown): string {
	return typeof value === 'string' ? value.trim() : '';
}

type TokenKind = 'jws' | 'jwe' | 'opaque';

type TokenClassification = {
	kind: TokenKind;
	token: string;
	parts: number;
	header: IDataObject;
};

/**
 * Normalize IdP token values before shape checks / STS.
 * Some IdPs or proxies inject whitespace/newlines into compact tokens.
 */
export function normalizeOidcToken(raw: string): string {
	let token = raw.trim();
	if (/^bearer\s+/i.test(token)) {
		token = token.replace(/^bearer\s+/i, '').trim();
	}
	return token.replace(/\s+/g, '');
}

function decodeJwtPart(part: string): IDataObject | null {
	try {
		const normalized = part.replace(/-/g, '+').replace(/_/g, '/');
		const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
		const json = Buffer.from(padded, 'base64').toString('utf8');
		const parsed = JSON.parse(json) as unknown;
		return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
			? (parsed as IDataObject)
			: null;
	} catch {
		return null;
	}
}

export function classifyOidcToken(raw: string): TokenClassification {
	const token = normalizeOidcToken(raw);
	const parts = token.split('.');
	const header = parts.length > 0 ? (decodeJwtPart(parts[0]) ?? {}) : {};

	// Compact JWS: header.payload.signature
	if (parts.length === 3 && parts.every((part) => part.length > 0)) {
		return { kind: 'jws', token, parts: 3, header };
	}

	// Compact JWE: header.encrypted_key.iv.ciphertext.tag (encrypted - STS cannot use this)
	if (parts.length === 5 && parts.every((part) => part.length > 0)) {
		return { kind: 'jwe', token, parts: 5, header };
	}

	return { kind: 'opaque', token, parts: parts.length, header };
}

/**
 * Safe JWT summary for errors: never includes the signature or full token.
 */
export function summarizeJwt(token: string): string {
	const classified = classifyOidcToken(token);
	const preview =
		classified.token.length > 24
			? `${classified.token.slice(0, 12)}…${classified.token.slice(-8)}`
			: classified.token;

	if (classified.kind === 'opaque') {
		const headerHint =
			Object.keys(classified.header).length > 0
				? ` header=${JSON.stringify(classified.header)}`
				: '';
		return `not a JWT (kind=opaque, parts=${classified.parts}, length=${classified.token.length}, preview=${JSON.stringify(preview)}${headerHint})`;
	}

	if (classified.kind === 'jwe') {
		return `encrypted JWE (parts=5, length=${classified.token.length}, header=${JSON.stringify(classified.header)}). STS needs a signed JWS (3 parts), not an encrypted token`;
	}

	const [, payloadPart] = classified.token.split('.');
	const payload = decodeJwtPart(payloadPart) ?? {};

	const claims: Record<string, unknown> = {
		alg: classified.header.alg,
		typ: classified.header.typ,
		kid: classified.header.kid,
		iss: payload.iss,
		aud: payload.aud,
		sub: payload.sub,
		azp: payload.azp,
		tid: payload.tid,
		exp: payload.exp,
		iat: payload.iat,
		token_use: payload.token_use,
		scp: payload.scp,
		scope: payload.scope,
	};

	const present = Object.entries(claims)
		.filter(([, value]) => value !== undefined && value !== null && value !== '')
		.map(([key, value]) => `${key}=${JSON.stringify(value)}`)
		.join(', ');

	return present || 'JWS with no recognizable claims';
}

function describeTokenResponseKeys(responseBody: IDataObject): string {
	const interesting = ['access_token', 'id_token', 'token_type', 'expires_in', 'scope'];
	const found = interesting
		.filter((key) => responseBody[key] !== undefined)
		.map((key) => {
			const value = responseBody[key];
			if (key === 'access_token' || key === 'id_token') {
				if (typeof value !== 'string') {
					return `${key}=${typeof value}`;
				}
				const classified = classifyOidcToken(value);
				if (classified.kind === 'jws') {
					return `${key}=JWS(len=${classified.token.length})`;
				}
				if (classified.kind === 'jwe') {
					return `${key}=JWE(len=${classified.token.length}, alg=${JSON.stringify(classified.header.alg)}, enc=${JSON.stringify(classified.header.enc)})`;
				}
				return `${key}=opaque(len=${classified.token.length}, parts=${classified.parts})`;
			}
			return `${key}=${JSON.stringify(value)}`;
		});
	return found.length ? found.join(', ') : `keys=${Object.keys(responseBody).join(',') || '(none)'}`;
}

/**
 * AWS STS Accepts RSA and ECDSA signatures only - not HMAC (HS*).
 * https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
 */
const STS_SUPPORTED_ALGS = new Set([
	'RS256',
	'RS384',
	'RS512',
	'ES256',
	'ES384',
	'ES512',
]);

function assertJwtForSts(token: string, tokenField: string, responseSummary: string): void {
	const classified = classifyOidcToken(token);
	if (classified.kind === 'jwe') {
		throw new UserError(
			[
				`Token field "${tokenField}" is an encrypted JWE, not a signed JWS.`,
				`STS AssumeRoleWithWebIdentity only accepts compact JWTs with 3 segments (header.payload.signature).`,
				`IdP response: ${responseSummary}.`,
				`Got: ${summarizeJwt(token)}.`,
				'Fix: disable JWE/token encryption for this OAuth client at the IdP (return signed id_token / JWT access_token).',
			].join(' '),
		);
	}

	if (classified.kind !== 'jws') {
		throw new UserError(
			[
				`Token field "${tokenField}" is not a JWT, so STS AssumeRoleWithWebIdentity will reject it.`,
				`IdP response: ${responseSummary}.`,
				`Got: ${summarizeJwt(token)}.`,
				'Fix: switch Token Property to "ID Token" if present, or configure the IdP so access_token is a JWT (audience/resource/scope).',
				'AWS error you would otherwise see: "The ID Token provided is not a valid JWT."',
			].join(' '),
		);
	}

	const alg = typeof classified.header.alg === 'string' ? classified.header.alg : '';
	if (alg && !STS_SUPPORTED_ALGS.has(alg)) {
		throw new UserError(
			[
				`Token field "${tokenField}" is signed with ${alg}, which AWS STS does not accept.`,
				'AssumeRoleWithWebIdentity requires RS256/RS384/RS512 or ES256/ES384/ES512 (not HS256/HS384/HS512).',
				`IdP response: ${responseSummary}.`,
				`Got: ${summarizeJwt(token)}.`,
				'Fix (Authentik): Application → Provider → set "Issuer Mode" / signing to RSA (RS256), or use a provider that signs with the provider certificate instead of a shared symmetric secret.',
			].join(' '),
		);
	}
}

export function stsFailureHints(webIdentityToken: string, detail: string): string {
	const classified = classifyOidcToken(webIdentityToken);
	const alg = typeof classified.header.alg === 'string' ? classified.header.alg : '';
	const hints: string[] = [];

	if (alg.startsWith('HS')) {
		hints.push(
			`${alg} is not supported by AWS STS - reconfigure the IdP to sign with RS256 (or ES256).`,
		);
	}

	hints.push(
		'Confirm the IAM OIDC identity provider URL matches iss exactly (including https://, no trailing slash mismatch).',
		'Confirm the role trust policy aud/sub conditions match aud/sub above.',
		'Confirm the OIDC provider thumbprint matches the IdP TLS cert.',
	);

	if (/not a valid JWT/i.test(detail)) {
		hints.push('Also try Token Property = ID Token if you sent access_token.');
	}

	return hints.join(' ');
}

/**
 * Exchange OAuth2 client credentials for a JWT from the IdP token URL.
 */
export async function fetchOidcToken(credentials: AwsOidcCredentials): Promise<string> {
	const accessTokenUrl = trimString(credentials.accessTokenUrl);
	const clientId = trimString(credentials.clientId);
	const clientSecret = trimString(credentials.clientSecret);
	const scope = trimString(credentials.scope);
	const audience = trimString(credentials.audience);
	const resource = trimString(credentials.resource);

	if (!accessTokenUrl || !clientId || !clientSecret) {
		throw new UserError('Token URL, Client ID, and Client Secret are required');
	}

	const body = new URLSearchParams({
		grant_type: 'client_credentials',
	});
	if (scope) {
		body.set('scope', scope);
	}
	if (audience) {
		body.set('audience', audience);
	}
	if (resource) {
		body.set('resource', resource);
	}

	const headers: Record<string, string> = {
		'Content-Type': 'application/x-www-form-urlencoded',
		Accept: 'application/json',
	};

	if (credentials.authentication === 'header') {
		headers.Authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
	} else {
		body.set('client_id', clientId);
		body.set('client_secret', clientSecret);
	}

	let response: Response;
	try {
		response = await fetch(accessTokenUrl, {
			method: 'POST',
			headers,
			body: body.toString(),
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		throw new UserError(`Failed to reach OAuth2 token URL: ${message}`);
	}

	const responseBody = (await response.json().catch(() => null)) as IDataObject | null;

	if (!response.ok) {
		const detail =
			typeof responseBody?.error_description === 'string'
				? responseBody.error_description
				: typeof responseBody?.error === 'string'
					? responseBody.error
					: `HTTP ${response.status}`;
		throw new UserError(`OAuth2 token request failed: ${detail}`);
	}

	if (!responseBody) {
		throw new UserError('OAuth2 token response was empty or not JSON');
	}

	const tokenField = credentials.tokenProperty || 'access_token';
	const responseSummary = describeTokenResponseKeys(responseBody);
	const token = responseBody[tokenField];
	if (typeof token !== 'string' || token.length === 0) {
		throw new UserError(
			[
				`OAuth2 token response did not include "${tokenField}".`,
				`IdP response: ${responseSummary}.`,
				'Client-credentials grants often return only access_token (sometimes opaque). id_token usually requires an OIDC scope such as openid.',
			].join(' '),
		);
	}

	assertJwtForSts(token, tokenField, responseSummary);
	const classified = classifyOidcToken(token);

	// Return normalized compact JWS (whitespace/Bearer stripped).
	return classified.token;
}

type LegacyHttpRequestOptions = IHttpRequestOptions & {
	/** HTTP Request node still sends the target on the legacy `uri` field. */
	uri?: string;
};

const AWS_REGION_PATTERN = /^[a-z]+(?:-[a-z]+)+-\d+$/;

/**
 * Reads the signing service and region from an AWS host, such as
 * `route53domains.us-east-1.amazonaws.com`. Returns `{}` for other hosts.
 */
function parseAwsHost(hostname: string): { service?: string; region?: string } {
	const labels = hostname.toLowerCase().split('.');
	const suffixIdx = labels.indexOf('amazonaws');
	if (suffixIdx === -1) return {};

	const hostLabels = labels.slice(0, suffixIdx);
	const regionIdx = hostLabels.findIndex((label) => AWS_REGION_PATTERN.test(label));
	const region = regionIdx === -1 ? undefined : hostLabels[regionIdx];

	// The service sits left of the region. Without a region, it is the last host label.
	let serviceIdx = regionIdx === -1 ? hostLabels.length - 1 : regionIdx - 1;
	if (hostLabels[serviceIdx] === 'dualstack') serviceIdx--;
	const service = serviceIdx >= 0 ? hostLabels[serviceIdx] : undefined;

	return { service, region };
}

/**
 * Maps an endpoint label to the SigV4 signing name. Same cases as n8n's
 * `getAwsSigningService`: the host label and the name AWS verifies differ for
 * these services.
 */
function getAwsSigningService(service: string): string {
	const baseService = service.replace(/-fips$/, '');
	if (/(^|\.)s3(-accesspoint|-control|-accelerate)?$/.test(baseService)) {
		return 's3';
	}
	switch (baseService) {
		case 'bedrock-runtime':
		case 'bedrock-agent':
		case 'bedrock-agent-runtime':
		case 'bedrock-data-automation':
		case 'bedrock-data-automation-runtime':
			return 'bedrock';
		case 'queue':
			return 'sqs';
		case 'email':
			return 'ses';
		default:
			return baseService;
	}
}

/** Plain objects and arrays are JSON bodies. Strings and buffers are already encoded. */
function shouldStringifyBody(value: unknown, headers: IDataObject): value is object {
	return (
		typeof value === 'object' &&
		value !== null &&
		!Buffer.isBuffer(value) &&
		!(value instanceof URLSearchParams) &&
		headers['Content-Length'] === undefined &&
		headers['content-length'] === undefined
	);
}

/**
 * Sign an outgoing HTTP request with temporary AWS credentials (SigV4).
 * Accepts both `url`/`baseURL` (IHttpRequestOptions) and `uri` (HTTP Request node).
 * The service and region come from the host when it is an AWS host. Otherwise
 * the `service` argument and `region` are used, with `sts` as the fallback service.
 */
export function signAwsRequest(
	requestOptions: IHttpRequestOptions,
	securityHeaders: AwsTemporaryCredentials,
	region: string,
	service?: string,
): IHttpRequestOptions {
	const legacyRequest = requestOptions as LegacyHttpRequestOptions;
	const target = requestOptions.url || legacyRequest.uri;
	const method = (requestOptions.method || 'GET').toUpperCase();
	let url: URL;

	try {
		if (requestOptions.baseURL) {
			url = new URL(target || '', requestOptions.baseURL);
		} else if (target) {
			url = new URL(target);
		} else {
			throw new UserError('Request URL is required for AWS signing');
		}
	} catch (error) {
		if (error instanceof UserError) throw error;
		throw new UserError('Invalid request URL for AWS signing');
	}

	if (requestOptions.qs) {
		for (const [key, value] of Object.entries(requestOptions.qs)) {
			if (value === undefined || value === null) continue;
			url.searchParams.append(key, String(value));
		}
	}

	const hostInfo = parseAwsHost(url.hostname);
	const signingService = getAwsSigningService(service ?? hostInfo.service ?? 'sts');
	const signingRegion = hostInfo.region ?? region;

	// Match n8n's awsGetSignInOptionsAndUpdateRequest: JSON-stringify object bodies,
	// and encode the HTTP Request node's `form` field as urlencoded. aws4 signs the
	// bytes that are actually sent.
	const headers: IDataObject = {
		...(requestOptions.headers as IDataObject | undefined),
	};
	const form = (requestOptions as IHttpRequestOptions & { form?: Record<string, string> }).form;
	const rawBody: unknown = requestOptions.body;
	let bodyContent: string | Buffer | undefined;

	if (form) {
		const params = new URLSearchParams();
		for (const key of Object.keys(form)) {
			params.append(key, form[key]);
		}
		bodyContent = params.toString();
		if (headers['Content-Type'] === undefined && headers['content-type'] === undefined) {
			headers['content-type'] = 'application/x-www-form-urlencoded';
		}
	} else if (shouldStringifyBody(rawBody, headers)) {
		bodyContent = JSON.stringify(rawBody);
	} else if (typeof rawBody === 'string' || Buffer.isBuffer(rawBody)) {
		bodyContent = rawBody;
	} else if (rawBody instanceof URLSearchParams) {
		bodyContent = rawBody.toString();
	} else if (rawBody !== undefined && rawBody !== null) {
		bodyContent = String(rawBody);
	}

	const signOpts = {
		host: url.host,
		method,
		path: `${url.pathname}${url.search}`,
		body: bodyContent,
		service: signingService,
		region: signingRegion,
		headers,
	} as Aws4Request;

	sign(signOpts, {
		accessKeyId: securityHeaders.accessKeyId,
		secretAccessKey: securityHeaders.secretAccessKey,
		sessionToken: securityHeaders.sessionToken,
	});

	const signedUrl = url.toString();
	const signedRequest: LegacyHttpRequestOptions = {
		...requestOptions,
		url: signedUrl,
		baseURL: undefined,
		qs: undefined,
		body: signOpts.body,
		headers: signOpts.headers as IHttpRequestOptions['headers'],
		method: method as IHttpRequestOptions['method'],
	};

	// The HTTP client prefers `url`, but keep `uri` aligned so the unsigned target is not sent.
	if (legacyRequest.uri !== undefined) {
		signedRequest.uri = signedUrl;
	}

	// `form` was encoded into `body`. Leaving it set makes the client send a second body.
	if (form) {
		delete (signedRequest as { form?: unknown }).form;
	}

	return signedRequest;
}
