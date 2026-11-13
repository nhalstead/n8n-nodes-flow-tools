import type { IDataObject } from 'n8n-workflow';
import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import { X509Certificate } from 'crypto';
import * as tls from 'tls';

type TlsSecureVersion = tls.SecureVersion | '';

const TLS_VERSION_ORDER: Record<tls.SecureVersion, number> = {
	TLSv1: 1,
	'TLSv1.1': 2,
	'TLSv1.2': 3,
	'TLSv1.3': 4,
};

interface TlsInfoOptions {
	host: string;
	port: number;
	servername: string;
	rejectUnauthorized: boolean;
	timeout: number;
	includeVerboseDetails: boolean;
	minVersion: TlsSecureVersion;
	maxVersion: TlsSecureVersion;
	expiresSoonDays: number;
}

function formatTlsVersionRange(minVersion: TlsSecureVersion, maxVersion: TlsSecureVersion): string {
	const min = minVersion || `default (${tls.DEFAULT_MIN_VERSION})`;
	const max = maxVersion || `default (${tls.DEFAULT_MAX_VERSION})`;
	return `min=${min}, max=${max}`;
}

/**
 * Node's defaults are typically min=TLSv1.2 / max=TLSv1.3. Setting only max=TLSv1.1
 * leaves the effective min at TLSv1.2, which is an empty protocol set.
 */
function assertValidTlsVersionRange(minVersion: TlsSecureVersion, maxVersion: TlsSecureVersion): void {
	const effectiveMin = minVersion || tls.DEFAULT_MIN_VERSION;
	const effectiveMax = maxVersion || tls.DEFAULT_MAX_VERSION;

	const minOrder = TLS_VERSION_ORDER[effectiveMin];
	const maxOrder = TLS_VERSION_ORDER[effectiveMax];
	if (minOrder === undefined || maxOrder === undefined || minOrder <= maxOrder) {
		return;
	}

	if (minVersion && maxVersion) {
		throw new Error(
			`Invalid TLS version range: Minimum TLS Version (${minVersion}) cannot be higher than Maximum TLS Version (${maxVersion}).`,
		);
	}

	if (!minVersion && maxVersion) {
		throw new Error(
			`Invalid TLS version range: Maximum TLS Version (${maxVersion}) is below Node's default minimum (${tls.DEFAULT_MIN_VERSION}). ` +
				`Also set Minimum TLS Version to ${maxVersion} or lower.`,
		);
	}

	if (minVersion && !maxVersion) {
		throw new Error(
			`Invalid TLS version range: Minimum TLS Version (${minVersion}) is above Node's default maximum (${tls.DEFAULT_MAX_VERSION}). ` +
				`Also set Maximum TLS Version to ${minVersion} or higher.`,
		);
	}
}

function isEmptyTlsProtocolRangeError(error: Error): boolean {
	const message = error.message.toLowerCase();
	const code = (error as NodeJS.ErrnoException).code;
	return message.includes('no protocols available') || code === 'ERR_SSL_NO_PROTOCOLS_AVAILABLE';
}

function isTlsProtocolVersionMismatchError(error: Error): boolean {
	const message = error.message.toLowerCase();
	const code = (error as NodeJS.ErrnoException).code;
	return (
		message.includes('alert protocol version') ||
		message.includes('ssl alert number 70') ||
		message.includes('wrong version number') ||
		code === 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION'
	);
}

function requestsLegacyTls(minVersion: TlsSecureVersion, maxVersion: TlsSecureVersion): boolean {
	const belowTls12 = (version: TlsSecureVersion) =>
		Boolean(version && TLS_VERSION_ORDER[version] < TLS_VERSION_ORDER['TLSv1.2']);

	return belowTls12(minVersion) || belowTls12(maxVersion);
}

function emptyTlsProtocolRangeMessage(
	options: Pick<TlsInfoOptions, 'host' | 'port' | 'minVersion' | 'maxVersion'>,
): string {
	const { host, port, minVersion, maxVersion } = options;
	const range = formatTlsVersionRange(minVersion, maxVersion);

	try {
		assertValidTlsVersionRange(minVersion, maxVersion);
	} catch (error) {
		if (error instanceof Error) {
			return `${error.message} (${host}:${port}, ${range})`;
		}
	}

	if (requestsLegacyTls(minVersion, maxVersion)) {
		return (
			`No TLS protocols available for ${host}:${port} (${range}). ` +
			`This Node/OpenSSL runtime has TLS 1.0/1.1 disabled (security level). ` +
			`This is a client-side limit, not proof that the destination rejects those versions.`
		);
	}

	return (
		`No TLS protocols available for ${host}:${port} (${range}). ` +
		`Check Min/Max TLS Version against Node defaults (min=${tls.DEFAULT_MIN_VERSION}, max=${tls.DEFAULT_MAX_VERSION}).`
	);
}

function toConnectionError(
	error: Error,
	options: Pick<TlsInfoOptions, 'host' | 'port' | 'minVersion' | 'maxVersion'>,
): Error {
	if (isEmptyTlsProtocolRangeError(error)) {
		return new Error(emptyTlsProtocolRangeMessage(options));
	}

	if (isTlsProtocolVersionMismatchError(error)) {
		const range = formatTlsVersionRange(options.minVersion, options.maxVersion);
		return new Error(
			`TLS protocol version mismatch with ${options.host}:${options.port} (${range}). ` +
				`The server rejected the client's offered versions. Try widening Min/Max TLS Version, or leave them as Default.`,
		);
	}

	return error;
}

/**
 * Parse OpenSSL-style SAN string: "DNS:example.com, DNS:www.example.com, IP Address:1.2.3.4"
 */
function parseSubjectAltNames(subjectaltname?: string): string[] {
	if (!subjectaltname) {
		return [];
	}

	return subjectaltname
		.split(',')
		.map((part) => part.trim())
		.filter(Boolean)
		.map((part) => {
			const separatorIndex = part.indexOf(':');
			if (separatorIndex === -1) {
				return part;
			}
			return part.slice(separatorIndex + 1).trim();
		});
}

/**
 * Walk issuerCertificate chain; stop on missing link or self-signed cycle.
 */
function collectCertificateChain(cert: tls.DetailedPeerCertificate): IDataObject[] {
	const chain: IDataObject[] = [];
	const seenFingerprints = new Set<string>();
	let current: tls.DetailedPeerCertificate | undefined = cert;

	while (current && Object.keys(current).length > 0) {
		const fingerprint = current.fingerprint256 || current.fingerprint;
		if (fingerprint && seenFingerprints.has(fingerprint)) {
			break;
		}
		if (fingerprint) {
			seenFingerprints.add(fingerprint);
		}

		chain.push({
				subject: current.subject,
				issuer: current.issuer,
				subjectCN: current.subject?.CN,
				issuerCN: current.issuer?.CN,
				serialNumber: current.serialNumber,
				fingerprint: current.fingerprint,
				fingerprint256: current.fingerprint256,
				valid_from: current.valid_from,
				valid_to: current.valid_to,
				bits: current.bits,
				subjectaltname: current.subjectaltname,
				subjectAltNames: parseSubjectAltNames(current.subjectaltname),
				ca: current.ca,
			} as IDataObject);

		const issuerCert: tls.DetailedPeerCertificate | undefined = current.issuerCertificate;
		if (!issuerCert || issuerCert === current) {
			break;
		}
		current = issuerCert;
	}

	return chain;
}

function getSignatureAlgorithm(socket: tls.TLSSocket): string | undefined {
	try {
		const x509: X509Certificate | undefined = socket.getPeerX509Certificate?.();
		return x509?.signatureAlgorithm;
	} catch {
		return undefined;
	}
}

function buildTlsResult(socket: tls.TLSSocket, options: TlsInfoOptions): IDataObject {
	const { host, port, servername, includeVerboseDetails, expiresSoonDays } = options;
	const cert = socket.getPeerCertificate(true);
	const cipher = socket.getCipher();

	const result: IDataObject = {
		host,
		port,
		servername,
		protocol: socket.getProtocol(),
		authorized: socket.authorized,
		authorizationError: socket.authorizationError,
		cipher: cipher
			? {
					name: cipher.name,
					standardName: cipher.standardName,
					version: cipher.version,
				}
			: undefined,
		alpn: socket.alpnProtocol || null,
	};

	if (!cert || Object.keys(cert).length === 0) {
		return result;
	}

	// Existing payload keys (keep names and shapes stable)
	if (includeVerboseDetails) {
		result.cert = cert;
		result.chain = collectCertificateChain(cert);
	}
	result.subject = cert.subject?.CN || cert.subject;
	result.issuer = cert.issuer?.CN || cert.issuer;
	result.valid_from = cert.valid_from;
	result.valid_to = cert.valid_to;

	if (cert.valid_to) {
		const diffTime = new Date(cert.valid_to).getTime() - Date.now();
		const daysRemaining = Math.round(diffTime / (1000 * 60 * 60 * 24));
		result.daysRemaining = daysRemaining;
		result.isExpired = daysRemaining < 0;
		result.expiresSoon = daysRemaining >= 0 && daysRemaining <= expiresSoonDays;
	}

	// Additive fields
	result.subjectCN = cert.subject?.CN;
	result.issuerCN = cert.issuer?.CN;
	result.subjectAltNames = parseSubjectAltNames(cert.subjectaltname);
	result.serialNumber = cert.serialNumber;
	result.fingerprint = cert.fingerprint;
	result.fingerprint256 = cert.fingerprint256;
	result.bits = cert.bits;
	result.sigalg = getSignatureAlgorithm(socket);

	return result;
}

/**
 * Opens a TLS connection, collects peer cert info, then always tears the socket down.
 * Settles the promise once so timeout/error/secure races cannot double-reject or leak.
 */
function fetchTlsInfo(options: TlsInfoOptions): Promise<IDataObject> {
	const { host, port, servername, rejectUnauthorized, timeout, minVersion, maxVersion } =
		options;

	assertValidTlsVersionRange(minVersion, maxVersion);

	return new Promise((resolve, reject) => {
		let settled = false;
		let socket: tls.TLSSocket | undefined;

		const settle = (err?: Error, result?: IDataObject) => {
			if (settled) {
				return;
			}
			settled = true;

			if (socket) {
				socket.removeAllListeners();
				socket.destroy();
				socket = undefined;
			}

			if (err) {
				reject(toConnectionError(err, { host, port, minVersion, maxVersion }));
				return;
			}

			resolve(result ?? {});
		};

		const connectionOptions: tls.ConnectionOptions = {
			host,
			port,
			servername,
			rejectUnauthorized,
		};

		if (minVersion) {
			connectionOptions.minVersion = minVersion;
		}
		if (maxVersion) {
			connectionOptions.maxVersion = maxVersion;
		}
		// OpenSSL 3 defaults (SECLEVEL) disable TLS 1.0/1.1 even when min/max allow them.
		// Lower the security level only when the user explicitly probes those versions.
		if (requestsLegacyTls(minVersion, maxVersion)) {
			connectionOptions.ciphers = 'DEFAULT:@SECLEVEL=0';
		}

		try {
			socket = tls.connect(connectionOptions, () => {
				try {
					settle(undefined, buildTlsResult(socket!, options));
				} catch (error) {
					settle(error instanceof Error ? error : new Error(String(error)));
				}
			});
		} catch (error) {
			settle(error instanceof Error ? error : new Error(String(error)));
			return;
		}

		socket.setTimeout(timeout);

		socket.once('timeout', () => {
			settle(new Error(`Connection timed out after ${timeout}ms`));
		});

		socket.once('error', (err) => {
			settle(err);
		});
	});
}

export class TlsInfo implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'TLS Info',
		name: 'tlsInfo',
		icon: 'file:tlsInfo.svg',
		group: ['transform'],
		usableAsTool: true,
		version: 1,
		subtitle: '={{$parameter["host"]}}',
		description: 'Retrieve TLS certificate and protocol information',
		defaults: {
			name: 'TLS Info',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Host',
				name: 'host',
				type: 'string',
				default: 'example.com',
				placeholder: 'example.com or 1.2.3.4',
				required: true,
				description:
					'Hostname or IP to connect to. For IP connects with SNI, set Server Name under Options.',
			},
			{
				displayName: 'Port',
				name: 'port',
				type: 'number',
				default: 443,
				required: true,
				description: 'The port number to connect to',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Expires Soon Days',
						name: 'expiresSoonDays',
						type: 'number',
						default: 30,
						description:
							'Number of days before expiry at which expiresSoon is set to true',
					},
					{
						displayName: 'Include Verbose Details',
						name: 'includeVerboseDetails',
						type: 'boolean',
						default: false,
						description:
							'Whether to include the full certificate object and issuer chain in the output',
					},
					{
						displayName: 'Maximum TLS Version',
						name: 'maxVersion',
						type: 'options',
						default: '',
						options: [
							{ name: 'Default', value: '' },
							{ name: 'TLSv1', value: 'TLSv1' },
							{ name: 'TLSv1.1', value: 'TLSv1.1' },
							{ name: 'TLSv1.2', value: 'TLSv1.2' },
							{ name: 'TLSv1.3', value: 'TLSv1.3' },
						],
						description:
							`Highest TLS protocol version to negotiate. Empty uses Node's default (${tls.DEFAULT_MAX_VERSION}). If set below the effective minimum (default ${tls.DEFAULT_MIN_VERSION}), also lower Minimum TLS Version.`,
					},
					{
						displayName: 'Minimum TLS Version',
						name: 'minVersion',
						type: 'options',
						default: '',
						options: [
							{ name: 'Default', value: '' },
							{ name: 'TLSv1', value: 'TLSv1' },
							{ name: 'TLSv1.1', value: 'TLSv1.1' },
							{ name: 'TLSv1.2', value: 'TLSv1.2' },
							{ name: 'TLSv1.3', value: 'TLSv1.3' },
						],
						description:
							`Lowest TLS protocol version to negotiate. Empty uses Node's default (${tls.DEFAULT_MIN_VERSION}). Values below TLSv1.2 temporarily lower OpenSSL's security level so those protocols can be offered.`,
					},
					{
						displayName: 'Reject Unauthorized',
						name: 'rejectUnauthorized',
						type: 'boolean',
						default: false,
						description:
							'Whether to reject connections with unauthorized certificates (e.g. self-signed). Default is false so you can still inspect invalid certs.',
					},
					{
						displayName: 'Server Name',
						name: 'servername',
						type: 'string',
						default: '',
						placeholder: 'www.example.com',
						description:
							'SNI hostname sent during the handshake. Use when Host is an IP (or differs from the cert name). If empty, Host is used.',
					},
					{
						displayName: 'Timeout',
						name: 'timeout',
						type: 'number',
						default: 10000,
						description: 'Connection timeout in milliseconds',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const host = (this.getNodeParameter('host', i) as string).trim();
				const port = this.getNodeParameter('port', i) as number;

				if (!host) {
					throw new NodeOperationError(this.getNode(), 'Host is required', { itemIndex: i });
				}

				if (!Number.isInteger(port) || port < 1 || port > 65535) {
					throw new NodeOperationError(this.getNode(), 'Port must be an integer between 1 and 65535', {
						itemIndex: i,
					});
				}

				const servername =
					(this.getNodeParameter('options.servername', i, '') as string).trim() || host;
				const rejectUnauthorized = this.getNodeParameter(
					'options.rejectUnauthorized',
					i,
					false,
				) as boolean;
				const timeout = this.getNodeParameter('options.timeout', i, 10000) as number;
				const includeVerboseDetails = this.getNodeParameter(
					'options.includeVerboseDetails',
					i,
					false,
				) as boolean;
				const minVersion = this.getNodeParameter('options.minVersion', i, '') as TlsSecureVersion;
				const maxVersion = this.getNodeParameter('options.maxVersion', i, '') as TlsSecureVersion;
				const expiresSoonDays = this.getNodeParameter(
					'options.expiresSoonDays',
					i,
					30,
				) as number;

				const tlsData = await fetchTlsInfo({
					host,
					port,
					servername,
					rejectUnauthorized,
					timeout,
					includeVerboseDetails,
					minVersion,
					maxVersion,
					expiresSoonDays,
				});

				returnData.push({
					json: tlsData,
					pairedItem: {
						item: i,
					},
				});

			} catch (error) {

				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error.message,
						},
						pairedItem: {
							item: i,
						},
					});
					continue;
				}

				throw new NodeOperationError(this.getNode(), error, { itemIndex: i });
			}
			
		}

		return [returnData];
	}
}
