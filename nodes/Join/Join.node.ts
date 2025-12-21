import type { NodeConnectionType } from 'n8n-workflow';
import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeBaseDescription,
	INodeTypeDescription,
} from 'n8n-workflow';
import { loadOptions } from './methods';
import { configuredInputs } from './utils';

export class Join implements INodeType {

	description: INodeTypeDescription = {
		displayName: 'Join Streams',
		name: 'join',
		icon: 'file:join.svg',
		group: ['transform'],
		version: 1,
		description: 'Merges multiple input items into a single item by combining all their properties.',
		defaults: {
			name: 'Join',
		},
		inputs: `={{(${configuredInputs})($parameter)}}`,
		outputs: ['main' as NodeConnectionType],
		usableAsTool: true,
		properties: [
			{
				displayName: 'Number of Inputs',
				name: 'numberInputs',
				type: 'options',
				noDataExpression: true,
				default: 1,
				options: [
					{
						name: '1',
						value: 1,
					},
					{
						name: '2',
						value: 2,
					},
					{
						name: '3',
						value: 3,
					},
					{
						name: '4',
						value: 4,
					},
					{
						name: '5',
						value: 5,
					},
					{
						name: '6',
						value: 6,
					},
					{
						name: '7',
						value: 7,
					},
					{
						name: '8',
						value: 8,
					},
					{
						name: '9',
						value: 9,
					},
					{
						name: '10',
						value: 10,
					},
				],
				validateType: 'number',
				description:
					'The number of data inputs you want to merge. The node waits for all connected inputs to be executed.',
			},
		],
	}

	constructor(baseDescription: INodeTypeBaseDescription) {
		this.description = {
			...this.description,
			...baseDescription,
		};
	}

	methods = {
		loadOptions,
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const numberInputs = this.getNodeParameter('numberInputs', 0, 2) as number;

		const allInputItems: INodeExecutionData[] = [];

		for (let inputIndex = 0; inputIndex < numberInputs; inputIndex++) {
			try {
				const inputItems = this.getInputData(inputIndex) ?? [];
				allInputItems.push(...inputItems);
			}
			catch (err) {
				// Do nothing, this input is not connected
			}
		}

		let finalObject: Record<string, any> = {};
		let finalBinary: Record<string, any> = {};

		for (let itemIndex = 0; itemIndex < allInputItems.length; itemIndex++) {
			const {json: itemJson} = allInputItems[itemIndex];
			finalObject = Object.assign(finalObject, itemJson);
			if (allInputItems[itemIndex].binary) {
				finalBinary = Object.assign(finalBinary, allInputItems[itemIndex].binary);
			}
		}

		const output: INodeExecutionData = {
			json: finalObject,
			binary: finalBinary,
			// Grab the first item's pairedItem if there is only one input item (this would set the source to pull data from)
			pairedItem: allInputItems.length > 1 ? allInputItems[0].pairedItem : undefined,
		};
		return [[output]];
	}

}
