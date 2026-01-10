import type { NodeConnectionType } from 'n8n-workflow';
import {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import get from 'lodash/get';

export class Lookup implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Lookup',
		name: 'lookup',
		icon: 'file:lookup.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{"for " + $parameter["needleKey"] + " lookup in " + $parameter["haystackKey"] + " as " + $parameter["outputKey"]}}',
		description: 'Lookup values from a collection of events provided.',
		defaults: {
			name: 'Lookup',
		},
		inputs: [
			{
				displayName: 'Input',
				type: 'main' as NodeConnectionType,
				required: true,
				maxConnections: 1,
			},
			{
				displayName: 'Reference Data',
				type: 'main' as NodeConnectionType,
				required: true,
				maxConnections: 1,
			},
		],
		outputs: ['main' as NodeConnectionType],
		usableAsTool: true,
		properties: [
			{
				displayName: 'Input Search Key',
				name: 'needleKey',
				type: 'string',
				default: 'id',
				description:
					'Property to pull the value used for the search. Supports dot notation (e.g. "user.key").',
			},
			{
				displayName: 'Reference Input Search Key',
				name: 'haystackKey',
				type: 'string',
				default: 'id',
				description:
					'Property to scan for the value to match in the input data. Supports dot notation (e.g. "user.key").',
			},
			{
				displayName: 'Output Key',
				name: 'outputKey',
				type: 'string',
				default: 'result',
				description: 'Property to output the found value to, if found',
			},
			{
				displayName: 'Output Entire Matched Item as Result',
				name: 'outputFullItem',
				type: 'boolean',
				default: true,
				description:
					'Whether output should return the whole item from the lookup will be returned or just the property specified',
			},
			{
				displayName: 'Keys to Pluck From Matched',
				name: 'outputFullItemKeys',
				type: 'string',
				default: 'id',
				description:
					'Property to output the full item to, if found. Supports dot notation (e.g. "user.name"). Only used if "Output Full Item" is false.',
				displayOptions: {
					show: {
						outputFullItem: [false],
					},
				},
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData(0);
		const lookupItems = this.getInputData(1);

		const needleKey = this.getNodeParameter('needleKey', 0, 'id') as string;
		const haystackKey = this.getNodeParameter('haystackKey', 0, 'id') as string;
		const outputKey = this.getNodeParameter('outputKey', 0, 'output') as string;

		const outputFullItem = this.getNodeParameter('outputFullItem', 0, true) as boolean;
		const outputFullItemKeys = this.getNodeParameter('outputFullItemKeys', 0, 'id') as string;

		// Lookup cache to store values that have already been resolved.
		const lookupMap = new Map<string, INodeExecutionData>();

		let item: INodeExecutionData;

		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			item = items[itemIndex];
			const needleValue = get(item.json, needleKey);

			if (!needleValue) {
				// If the haystack value is not present, set the output to null
				item.json[outputKey] = null;
				continue;
			}

			if (typeof needleValue !== 'string' && typeof needleValue !== 'number') {
				throw new NodeOperationError(
					this.getNode(),
					`Needle value for key "${needleKey}" must be a string or number, got ${typeof needleValue}`,
					{
						itemIndex,
					},
				);
			}

			let outputValue: INodeExecutionData | null = null;

			// Check if the value is already in the lookup cache
			if (lookupMap.has(needleValue.toString())) {
				outputValue = lookupMap.get(needleValue.toString()) as INodeExecutionData;
			} else {
				// If not found in cache, search through the lookup items
				const foundValue = lookupItems.find((lookupItem: INodeExecutionData) => {
					const lookupValue = get(lookupItem.json, haystackKey);

					if (lookupValue == null) {
						// If the lookup value is null or undefined, skip this item
						return false;
					}

					if (typeof lookupValue !== 'string' && typeof lookupValue !== 'number') {
						throw new NodeOperationError(
							this.getNode(),
							`Haystack value for key "${haystackKey}" must be a string or number, got ${typeof lookupValue}`,
							{
								itemIndex,
							},
						);
					}
					return lookupValue.toString() === needleValue.toString();
				});

				// Store the found value in the cache for future lookups
				if (foundValue) {
					lookupMap.set(needleValue.toString(), foundValue);
					outputValue = foundValue;
				}
			}

			// If no match was found, set the output to null
			if (outputValue == null) {
				item.json[outputKey] = null;
				continue;
			}

			// Otherwise, set only the specified key from the matched item
			const keysToPluck = outputFullItemKeys.split(',').map((key) => key.trim());

			// If outputFullItem is true, set the entire matched item
			if (outputFullItem || keysToPluck.length == 0) {
				item.json[outputKey] = outputValue.json;
				continue;
			}

			if (keysToPluck.length == 1) {
				// If keysToPluck is an array, pluck the first one (supports dot notation)
				item.json[outputKey] = get(outputValue.json, keysToPluck[0]) as IDataObject[string];
				continue;
			}

			// If multiple keys are specified, set the output to an object of the selected keys
			const pluckedResult: IDataObject = {};
			for (const keyPath of keysToPluck) {
				// Use the last segment of the path as the output key name
				const outputKeyName = keyPath.includes('.') ? keyPath.split('.').pop()! : keyPath;
				pluckedResult[outputKeyName] = get(outputValue.json, keyPath) as IDataObject[string];
			}
			item.json[outputKey] = pluckedResult;
		}

		return [items];
	}
}
