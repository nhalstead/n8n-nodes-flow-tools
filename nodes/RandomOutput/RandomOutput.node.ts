import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeBaseDescription,
	INodeTypeDescription,
} from 'n8n-workflow';
import { configuredOutput } from './utils';

import type {
	ILoadOptionsFunctions,
	INodeParameters,
	INodePropertyOptions,
	NodeConnectionType,
} from 'n8n-workflow';

export class RandomOutput implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Random Output',
		name: 'randomOutput',
		icon: 'file:randomOutput.svg',
		group: ['organization'],
		version: 1,
		description: 'Using JavaScript random, send input items to random output.',
		defaults: {
			name: 'Random Output',
		},
		inputs: ['main' as NodeConnectionType],
		outputs: `={{(${configuredOutput})($parameter)}}`,
		usableAsTool: true,
		properties: [
			{
				displayName: 'Number of Outputs',
				name: 'numberOutputs',
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
				description: 'The number of data outputs you want to send events',
			},
			{
				displayName: 'Output Element',
				name: 'outputElement',
				type: 'options',
				noDataExpression: true,
				default: 'inputItem',
				options: [
					{
						name: 'Input Item',
						value: 'inputItem',
					},
					{
						name: 'Output Index',
						value: 'outputIndex',
					},
				],
				validateType: 'string',
				description: 'What to output on the different outputs',
			},
			{
				displayName: 'Options',
				name: 'options',
				type: 'collection',
				placeholder: 'Add Field',
				default: {},
				options: [
					{
						displayName: 'Force All Items to Output',
						name: 'forceOutput',
						type: 'number',
						default: null,
						description:
							'Bypass Random Output node behavior and send each item to a select output (useful for testing)',
					},
					{
						displayName: "Allow 'Force All Items to Output' in Production",
						name: 'forceOutputInProduction',
						type: 'boolean',
						default: false,
						description:
							'Whether to allow \'Force All Items to Output\' to be used when the workflow is not in test mode',
					},
				],
			},
		],
	};

	constructor(baseDescription: INodeTypeBaseDescription) {
		this.description = {
			...this.description,
			...baseDescription,
		};
	}

	methods = {
		loadOptions: {
			async getFallbackOutputOptions(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]> {
				const rules = (this.getCurrentNodeParameter('numberOutputs') as INodeParameters[]) ?? [];

				const outputOptions: INodePropertyOptions[] = [];

				for (const [index, rule] of rules.entries()) {
					outputOptions.push({
						name: `Output ${rule.outputKey || index}`,
						value: index,
						description: `Items will be sent to the same output when the random number equals ${index + 1}`,
					});
				}

				return outputOptions;
			},
		},
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const numberOutputs = this.getNodeParameter('numberOutputs', 0, 2) as number;
		const outputElement = this.getNodeParameter('outputElement', 0, 'inputItem') as string;
		const forceOutputInProduction = this.getNodeParameter('options.forceOutputInProduction', 0, false) as boolean;
		const forceOutput = this.getNodeParameter('options.forceOutput', 0, null) as number;

		// Loop over the input items, use javascript random to decide which output to send each item to
		const allOutputs: INodeExecutionData[][] = Array.from({ length: numberOutputs }, () => []);

		const inputItems = this.getInputData(0);

		for (let itemIndex = 0; itemIndex < inputItems.length; itemIndex++) {
			const randomOutputIndex = Math.floor(Math.random() * numberOutputs);
			const isTestWorkflow = this.getWorkflowDataProxy(itemIndex)['$execution'].mode === 'test';
			let finalOutputIndex = randomOutputIndex;

			// Allow forcing all items to one output to create predictable output for testing
			if ((isTestWorkflow || forceOutputInProduction) && forceOutput !== null) {
				let forcedOutputIndex = forceOutput;

				if (forcedOutputIndex < 0 || forcedOutputIndex >= numberOutputs) {
					// default to output index 0 if the index is out of range
					forcedOutputIndex = 0;
				}

				finalOutputIndex = forcedOutputIndex;
			}

			switch (outputElement) {
				case 'outputIndex':
					const newItem: INodeExecutionData = {
						json: { outputIndex: finalOutputIndex },
					};
					allOutputs[finalOutputIndex].push(newItem);
					break;
				case 'inputItem':
				default:
					allOutputs[finalOutputIndex].push(inputItems[itemIndex]);
			}
		}

		return allOutputs;
	}
}
