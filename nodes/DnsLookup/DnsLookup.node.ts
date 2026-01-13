import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';

import { promises as dnsPromises } from 'dns';

export class DnsLookup implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'DNS Lookup',
		name: 'dnsLookup',
		icon: 'file:dnsLookup.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["domain"]}} ({{$parameter["recordType"]}})',
		description: 'Fetch DNS records using a specific resolver',
		defaults: {
			name: 'DNS Lookup',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Domain/Zone Name',
				name: 'domain',
				type: 'string',
				default: '',
				placeholder: 'google.com',
				description: 'The domain or zone name to query',
				required: true,
			},
			{
				displayName: 'Record Type',
				name: 'recordType',
				type: 'options',
				options: [
					{ name: 'A', value: 'A' },
					{ name: 'AAAA', value: 'AAAA' },
					{ name: 'ANY', value: 'ANY' },
					{ name: 'CNAME', value: 'CNAME' },
					{ name: 'MX', value: 'MX' },
					{ name: 'NS', value: 'NS' },
					{ name: 'PTR', value: 'PTR' },
					{ name: 'SOA', value: 'SOA' },
					{ name: 'SRV', value: 'SRV' },
					{ name: 'TXT', value: 'TXT' },
				],
				default: 'A',
				description: 'The type of DNS record to fetch',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Option',
				default: {},
				options: [
					{
						displayName: 'Custom Resolver Server',
						name: 'server',
						type: 'string',
						default: '',
						placeholder: '8.8.8.8',
						description: 'IP address of a specific DNS server to query. Leave empty to use system default.',
					},
					{
						displayName: 'Timeout',
						name: 'timeout',
						type: 'number',
						default: 5000,
						description: 'Query timeout in milliseconds',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const { Resolver } = dnsPromises;

		for (let i = 0; i < items.length; i++) {
			try {
				const domain = this.getNodeParameter('domain', i) as string;
				const recordType = this.getNodeParameter('recordType', i) as string;
				const server = this.getNodeParameter('options.server', i, '') as string;
				const timeout = this.getNodeParameter('options.timeout', i, 5000) as number;

				const resolver = new Resolver();

				if (server) {
					resolver.setServers([server]);
				}

				// We cast recordType to 'any' because the strict types for .resolve
				// are specific strings, but our 'recordType' is a general string.
				const resolvePromise = resolver.resolve(domain, recordType as any);

				let timeoutId: NodeJS.Timeout | undefined;
				const timeoutPromise = new Promise((_, reject) => {
					timeoutId = setTimeout(() => {
						reject(new Error(`DNS query timed out after ${timeout}ms`));
					}, timeout);
				});

				try {
					const records = await Promise.race([resolvePromise, timeoutPromise]);
					if (timeoutId) {
						clearTimeout(timeoutId);
					}

					returnData.push({
						json: {
							domain,
							recordType,
							resolver: server || 'system_default',
							success: true,
							records: records as any,
						},
						pairedItem: {
							item: i,
						},
					});
				} catch (error) {
					if (timeoutId) {
						clearTimeout(timeoutId);
					}
					throw error;
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error.message,
							success: false,
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
