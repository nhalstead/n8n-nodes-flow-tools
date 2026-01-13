import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import * as tls from 'tls';

export class TlsInfo implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'TLS Info',
		name: 'tlsInfo',
		icon: 'file:tlsInfo.svg',
		group: ['transform'],
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
				default: 'www.google.com',
				required: true,
				description: 'The host name to connect to',
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
						displayName: 'Include Verbose Details',
						name: 'includeVerboseDetails',
						type: 'boolean',
						default: false,
						description: 'Whether to include the full certificate object in the output',
					},
					{
						displayName: 'Reject Unauthorized',
						name: 'rejectUnauthorized',
						type: 'boolean',
						default: false,
						description: 'Whether to reject connections with unauthorized certificates (e.g. self-signed)',
					},
					{
						displayName: 'Server Name',
						name: 'servername',
						type: 'string',
						default: '',
						description: 'Host name for SNI (Server Name Indication). If empty, the Host value will be used.',
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
				const host = this.getNodeParameter('host', i) as string;
				const port = this.getNodeParameter('port', i) as number;

				const servername = (this.getNodeParameter('options.servername', i, '') as string) || host;
				const rejectUnauthorized = this.getNodeParameter('options.rejectUnauthorized', i, false) as boolean;
				const timeout = this.getNodeParameter('options.timeout', i, 10000) as number;
				const includeVerboseDetails = this.getNodeParameter(
					'options.includeVerboseDetails',
					i,
					false,
				) as boolean;

				const tlsData = await new Promise((resolve, reject) => {
					const options: tls.ConnectionOptions = {
						host,
						port,
						servername,
						rejectUnauthorized,
					};

					const socket = tls.connect(options, () => {
						const cert = socket.getPeerCertificate(true);
						const protocol = socket.getProtocol();

						const result: any = {
							protocol,
							authorized: socket.authorized,
							authorizationError: socket.authorizationError,
						};

						if (cert && Object.keys(cert).length > 0) {
							if (includeVerboseDetails) {
								result.cert = cert;
							}
							result.subject = cert.subject?.CN || cert.subject;
							result.issuer = cert.issuer?.CN || cert.issuer;
							result.valid_from = cert.valid_from;
							result.valid_to = cert.valid_to;

							// Add convenience fields
							if (cert.valid_to) {
								const validTo = new Date(cert.valid_to);
								const now = new Date();
								const diffTime = validTo.getTime() - now.getTime();
								const diffDays = Math.round(diffTime / (1000 * 60 * 60 * 24));
								result.daysRemaining = diffDays;
							}
						}

						socket.end();
						resolve(result);
					});

					socket.on('error', (err) => {
						socket.destroy();
						reject(err);
					});

					socket.setTimeout(timeout, () => {
						socket.destroy();
						reject(new Error(`Connection timed out after ${timeout}ms`));
					});
				});

				returnData.push({
					json: tlsData as any,
					pairedItem: i,
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error.message,
						},
						pairedItem: i,
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error, { itemIndex: i });
			}
		}

		return [returnData];
	}
}
