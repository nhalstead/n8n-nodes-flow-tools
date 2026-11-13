import type {
	IDataObject,
	IExecuteFunctions,
	IHttpRequestOptions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeOperationError } from 'n8n-workflow';

function getStsBaseUrl(region: string): string {
	const domain = region.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
	return `https://sts.${region}.${domain}`;
}

function extractCallerIdentity(response: IDataObject): IDataObject {
	const wrapped = response.GetCallerIdentityResponse as IDataObject | undefined;
	const result = (wrapped?.GetCallerIdentityResult ?? response) as IDataObject;

	return {
		Account: result.Account,
		Arn: result.Arn,
		UserId: result.UserId,
	};
}

export class AwsSts implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'AWS STS',
		name: 'awsSts',
		icon: { light: 'file:awsSts.svg', dark: 'file:awsSts.dark.svg' },
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"]}}',
		description: 'Call AWS Security Token Service (STS)',
		defaults: {
			name: 'AWS STS',
		},
		inputs: ['main'],
		outputs: ['main'],
		credentials: [
			{
				name: 'aws',
				required: true,
				displayOptions: {
					show: {
						authentication: ['iam'],
					},
				},
			},
			{
				name: 'awsOidcApi',
				required: true,
				displayOptions: {
					show: {
						authentication: ['oidc'],
					},
				},
			},
		],
		properties: [
			{
				displayName: 'Authentication',
				name: 'authentication',
				type: 'options',
				options: [
					{
						name: 'AWS (IAM)',
						value: 'iam',
					},
					{
						name: 'AWS (OIDC)',
						value: 'oidc',
					},
				],
				default: 'oidc',
			},
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Caller Identity',
						value: 'callerIdentity',
					},
				],
				default: 'callerIdentity',
			},
			{
				displayName: 'Operation',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				displayOptions: {
					show: {
						resource: ['callerIdentity'],
					},
				},
				options: [
					{
						name: 'Get',
						value: 'get',
						description: 'Return details about the IAM identity used in the request',
						action: 'Get caller identity',
					},
				],
				default: 'get',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const authentication = this.getNodeParameter('authentication', 0) as 'iam' | 'oidc';
		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;
		const credentialsType = authentication === 'oidc' ? 'awsOidcApi' : 'aws';

		for (let i = 0; i < items.length; i++) {
			try {
				if (resource !== 'callerIdentity' || operation !== 'get') {
					throw new NodeOperationError(
						this.getNode(),
						`The operation "${operation}" is not supported for resource "${resource}"`,
						{ itemIndex: i },
					);
				}

				const credentials = await this.getCredentials(credentialsType);
				const region = String(credentials.region || 'us-east-1').trim();

				const requestOptions: IHttpRequestOptions = {
					method: 'POST',
					baseURL: getStsBaseUrl(region),
					url: '/',
					qs: {
						Action: 'GetCallerIdentity',
						Version: '2011-06-15',
						service: 'sts',
					},
					headers: {
						Accept: 'application/json',
						'Content-Type': 'application/x-www-form-urlencoded',
					},
					json: true,
				};

				const response = (await this.helpers.requestWithAuthentication.call(
					this,
					credentialsType,
					requestOptions,
				)) as IDataObject;

				returnData.push({
					json: extractCallerIdentity(response),
					pairedItem: { item: i },
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error instanceof Error ? error.message : String(error),
						},
						pairedItem: { item: i },
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}
