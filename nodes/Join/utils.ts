
import type { INodeParameters } from 'n8n-workflow';

/**
 * Copied from packages/nodes-base/nodes/Merge/v3/helpers/utils.ts
 * Used a a template literal to generate the inputs for the node
 *
 * @param parameters
 */
export const configuredInputs = (parameters: INodeParameters) => {
	return Array.from({ length: (parameters.numberInputs as number) || 2 }, (_, i) => ({
		type: 'main',
		displayName: `Input ${(i + 1).toString()}`,
	}));
};
