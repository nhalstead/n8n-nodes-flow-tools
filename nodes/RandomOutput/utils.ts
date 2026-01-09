
import type { INodeParameters } from 'n8n-workflow';

/**
 * Copied from packages/nodes-base/nodes/Merge/v3/helpers/utils.ts
 * Used a template literal to generate the outputs for the node
 *
 * @param parameters
 */
export const configuredOutput = (parameters: INodeParameters) => {
	return Array.from({ length: (parameters.numberOutputs as number) || 2 }, (_, i) => ({
		type: 'main',
		displayName: `Output ${(i + 1).toString()}`,
	}));
};
