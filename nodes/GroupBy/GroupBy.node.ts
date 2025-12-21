import {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType, NodeOperationError,
} from 'n8n-workflow';

enum OutputFormat {
	STREAM_ELEMENTS = 'streamElements',
	OBJECT_WITH_ITEMS = 'objectWithItems',
	OBJECT_ENTRIES = 'objectEntries',
}

export class GroupBy implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'GroupBy',
		name: 'groupBy',
		icon: 'file:groupBy.svg',
		group: ['transform'],
		version: 1,
		description: 'Groups items by a key, optionally as stream items or as an object with an array of items',
		defaults: {
			name: 'Group By',
		},
		inputs: [
			{
				displayName: "Input",
				type: NodeConnectionType.Main,
				required: true,
				maxConnections: 1
			}
		],
		outputs: [NodeConnectionType.Main],
		usableAsTool: true,
		properties: [
			{
				displayName: 'Key to Group By',
				name: 'keyOn',
				type: 'string',
				default: 'id',
				description: 'Property to pull the value used for grouping',
			},
			{
				displayName: "Output Format",
				name: "outputFormat",
				type: "options",
				default: "streamElements",
				options: [
					{
						name: "Stream Elements",
						value: OutputFormat.STREAM_ELEMENTS,
						description: "Outputs one item per group, each group is emitted as a separate item",
					},
					{
						name: "Object",
						value: OutputFormat.OBJECT_WITH_ITEMS,
						description: "Outputs a single object, where each key contains an array of grouped items",
					},
					{
						name: "Object Entries",
						value: OutputFormat.OBJECT_ENTRIES,
						description: "Outputs a single object, with items containing groups as string-keyed properties",
					}
				],
			}
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData(0);
		const keyOn = this.getNodeParameter('keyOn', 0, 'id') as string;
		const outputFormat = this.getNodeParameter('outputFormat', 0, OutputFormat.STREAM_ELEMENTS) as string;

		const groups : Record<string, INodeExecutionData[]> = {}

		for (const item of items) {
			const keyValue = item.json[ keyOn ];
			const keyValueAsString = String(keyValue);

			if (!groups[ keyValueAsString ]) groups[ keyValueAsString ] = [];

			delete item.json[ keyOn ]; // Remove the key
			groups[ keyValueAsString ].push(item);
		}

		let output: INodeExecutionData[];

		if (outputFormat === OutputFormat.STREAM_ELEMENTS) {
			// Remap the groups to the expected output format for n8n nodes
			output =  Object.entries(groups)
				.map(([key, items], index) => {
					return {
						json: {
							items: items,
							key: key,
							index: index
						},
						// Returns the first item as the source for parent data.
						pairedItem: items.length > 0 ? items[0].pairedItem : undefined,
					}
				})
		}
		else {
			// We want to group the items as an object with an array of items, without the extra metadata
			const groupObjects : Record<string, IDataObject[]> = {};

			for (const key of Object.keys(groups)) {
				groupObjects[key] = groups[key].map((item) => item.json);
			}

			if (outputFormat === OutputFormat.OBJECT_WITH_ITEMS) {
				output = [{
					json: groupObjects,
					// Returns the first item as the source for parent data.
					pairedItem: items.length > 0 ? items[0].pairedItem : undefined,
				}];
			}
			else if (outputFormat === OutputFormat.OBJECT_ENTRIES) {
				// Convert the object to an array of entries
				output = [
					{
						json: {
							items: Object.entries(groupObjects).map(([key, values]) => {
								return {
									key: key,
									values: values,
								};
							}),
						},
						// Returns the first item as the source for parent data.
						pairedItem: items.length > 0 ? items[0].pairedItem : undefined,
					},
				];
			}
			else {
				throw new NodeOperationError(this.getNode(), `Unknown output format: ${outputFormat}`);
			}
		}

		return [output];
	}
}
