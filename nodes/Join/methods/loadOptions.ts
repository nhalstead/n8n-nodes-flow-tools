import type { ILoadOptionsFunctions, INodePropertyOptions } from 'n8n-workflow';

export async function getInputs(this: ILoadOptionsFunctions): Promise<INodePropertyOptions[]> {
	const numberOfInputs = this.getNodeParameter('numberInputs', 2) as number;

	const returnData: INodePropertyOptions[] = [];

	for (let i = 0; i < numberOfInputs; i++) {
		returnData.push({
			name: `${i + 1}`,
			value: i + 1,
		});
	}

	return returnData;
}
