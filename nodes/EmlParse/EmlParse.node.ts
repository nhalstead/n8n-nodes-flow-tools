import type { NodeConnectionType } from 'n8n-workflow';
import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import get from 'lodash/get';
import { simpleParser, Source } from 'mailparser';

export class EmlParse implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Parse EML',
		name: 'emlParse',
		icon: 'file:emlParse.svg',
		group: ['transform'],
		version: 1,
		description:
			'Parse EML files to extract useful information such as sender, recipient, subject, and body content.',
		defaults: {},
		inputs: [
			{
				displayName: 'Input',
				type: 'main' as NodeConnectionType,
				required: true,
				maxConnections: 1,
			},
		],
		outputs: ['main' as NodeConnectionType],
		usableAsTool: true,
		properties: [
			{
				displayName: 'Source',
				name: 'sourceKey',
				type: 'string',
				default: 'data',
				description:
					'Property to pull the value used for grouping. Supports dot notation (e.g. "user.key").',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				options: [
					{
						displayName: 'Disable Dot Notation',
						name: 'disableDotNotation',
						type: 'boolean',
						default: false,
						description:
							'Whether to disallow referencing child fields using `parent.child` in the field name',
					},
				],
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData(0);
		const sourceKey = this.getNodeParameter('sourceKey', 0, 'id') as string;
		const disableDotNotation = this.getNodeParameter(
			'options.disableDotNotation',
			0,
			false,
		) as boolean;

		let output: INodeExecutionData[] = [];

		for (const [index, item] of items.entries()) {

			// If the key is defined in binary, use that first
			if (item.binary && item.binary[sourceKey]) {
				const sourceData = item.binary[sourceKey];
				const binaryDataBuffer = await this.helpers.getBinaryDataBuffer(index, sourceData);
				const parsedData = await simpleParser(binaryDataBuffer);
				output.push({
					json: Object(parsedData),
				});
				continue;
			}

			// Pull data from JSON if not found in binary
			const source = disableDotNotation ? item.json[sourceKey] : get(item.json, sourceKey);
			const parsedData = await simpleParser(source as Source, {});
			output.push({
				json: Object(parsedData),
			});
		}

		return [output];
	}
}
