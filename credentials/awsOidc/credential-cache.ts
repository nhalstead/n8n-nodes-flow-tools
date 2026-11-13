import { createHash } from 'node:crypto';

import { fromWebToken } from '@aws-sdk/credential-providers';
import { UserError } from 'n8n-workflow';

import {
	type AwsOidcCredentials,
	type AwsTemporaryCredentials,
	fetchOidcToken,
	stsFailureHints,
	summarizeJwt,
} from './utils';

/** Refresh STS credentials this long before Expiration (matches common AWS SDK skew). */
const REFRESH_WINDOW_MS = 5 * 60 * 1000;

/** Cap process-local entries so rotated credentials cannot grow the map forever. */
const MAX_CACHED_PROVIDERS = 32;

type CachedSession = AwsTemporaryCredentials & {
	expiration?: Date;
};

type CacheEntry = {
	session?: CachedSession;
	inflight?: Promise<CachedSession>;
	lastUsed: number;
};

/**
 * Process-local sessions keyed by a fingerprint of the credential configuration.
 * Different credential configs never share a cached STS session.
 */
const sessionsByFingerprint = new Map<string, CacheEntry>();

function trimString(value: unknown): string {
	return typeof value === 'string' ? value.trim() : '';
}

/**
 * Stable fingerprint for one logical credential config.
 * Secrets are hashed into the key so two credentials with the same public fields
 * but different secrets do not share a cached STS session.
 */
export function fingerprintAwsOidcCredentials(credentials: AwsOidcCredentials): string {
	const secretHash = createHash('sha256')
		.update(trimString(credentials.clientSecret))
		.digest('hex');

	const material = [
		trimString(credentials.region),
		trimString(credentials.accessTokenUrl),
		trimString(credentials.clientId),
		secretHash,
		trimString(credentials.scope),
		trimString(credentials.audience),
		trimString(credentials.resource),
		credentials.authentication ?? '',
		credentials.tokenProperty ?? '',
		trimString(credentials.roleArn),
		trimString(credentials.roleSessionName),
		String(credentials.durationSeconds ?? ''),
	].join('\u0000');

	return createHash('sha256').update(material).digest('hex');
}

function isFresh(session: CachedSession): boolean {
	if (!session.expiration) {
		return false;
	}
	return session.expiration.getTime() - Date.now() > REFRESH_WINDOW_MS;
}

function evictIfNeeded(retainFingerprint: string): void {
	if (sessionsByFingerprint.size <= MAX_CACHED_PROVIDERS) {
		return;
	}

	let oldestKey: string | undefined;
	let oldestUsed = Number.POSITIVE_INFINITY;
	for (const [key, entry] of sessionsByFingerprint) {
		if (key === retainFingerprint) continue;
		if (entry.lastUsed < oldestUsed) {
			oldestUsed = entry.lastUsed;
			oldestKey = key;
		}
	}
	if (oldestKey) {
		sessionsByFingerprint.delete(oldestKey);
	}
}

async function fetchNewSession(credentials: AwsOidcCredentials): Promise<CachedSession> {
	const token = await fetchOidcToken(credentials);
	const region = trimString(credentials.region) || 'us-east-1';
	const roleArn = trimString(credentials.roleArn);
	const roleSessionName = trimString(credentials.roleSessionName) || 'n8n-oidc-session';

	if (!roleArn) {
		throw new UserError('Role ARN is required');
	}

	const durationSeconds = Number(credentials.durationSeconds);

	try {
		const resolved = await fromWebToken({
			webIdentityToken: token,
			roleArn,
			roleSessionName,
			...(Number.isFinite(durationSeconds) && durationSeconds > 0
				? { durationSeconds: Math.trunc(durationSeconds) }
				: {}),
			clientConfig: {
				region,
				maxAttempts: 1,
				requestHandler: { requestTimeout: 10_000, connectionTimeout: 5_000 },
			},
		})();

		return {
			accessKeyId: resolved.accessKeyId,
			secretAccessKey: resolved.secretAccessKey,
			sessionToken: resolved.sessionToken ?? '',
			expiration: resolved.expiration,
		};
	} catch (error) {
		if (error instanceof UserError) throw error;
		const message = error instanceof Error ? error.message : String(error);
		throw new UserError(
			[
				`STS AssumeRoleWithWebIdentity failed: ${message}`,
				`WebIdentityToken summary: ${summarizeJwt(token)}.`,
				stsFailureHints(token, message),
			].join(' '),
		);
	}
}

/**
 * Resolve temporary AWS credentials for this OIDC credential config.
 * Reuses a process-local, fingerprint-scoped session so OAuth2 + STS are not
 * called on every request while the AWS session is still valid.
 */
export async function resolveAwsOidcTemporaryCredentials(
	credentials: AwsOidcCredentials,
): Promise<AwsTemporaryCredentials> {
	const fingerprint = fingerprintAwsOidcCredentials(credentials);
	let entry = sessionsByFingerprint.get(fingerprint);
	if (!entry) {
		entry = { lastUsed: Date.now() };
		sessionsByFingerprint.set(fingerprint, entry);
		evictIfNeeded(fingerprint);
	}
	entry.lastUsed = Date.now();

	if (entry.session && isFresh(entry.session)) {
		return {
			accessKeyId: entry.session.accessKeyId,
			secretAccessKey: entry.session.secretAccessKey,
			sessionToken: entry.session.sessionToken,
		};
	}

	if (!entry.inflight) {
		entry.inflight = fetchNewSession(credentials).finally(() => {
			const current = sessionsByFingerprint.get(fingerprint);
			if (current) {
				current.inflight = undefined;
			}
		});
	}

	const session = await entry.inflight;
	entry.session = session;

	return {
		accessKeyId: session.accessKeyId,
		secretAccessKey: session.secretAccessKey,
		sessionToken: session.sessionToken,
	};
}

/** Test helper - clears the process-local session cache. */
export function clearAwsOidcCredentialCache(): void {
	sessionsByFingerprint.clear();
}
