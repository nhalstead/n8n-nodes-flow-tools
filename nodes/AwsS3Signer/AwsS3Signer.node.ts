import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import * as crypto from 'crypto';

export class AwsS3Signer implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'AWS S3 Signer',
		name: 'awsS3Signer',
		icon: 'file:awsS3Signer.svg',
		group: ['transform'],
		version: 1,
		description: 'Sign an S3 URL with external credentials',
		defaults: {
			name: 'AWS S3 Signer',
		},
		credentials: [
			{
				name: 'aws',
				required: true,
			},
		],
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Bucket Name',
				name: 'bucketName',
				type: 'string',
				default: '',
				required: true,
				description: 'Name of the S3 bucket',
			},
			{
				displayName: 'Region',
				name: 'region',
				type: 'string',
				default: '',
				description: 'AWS Region. If not specified, the region from the credentials will be used.',
			},
			{
				displayName: 'Object Path',
				name: 'objectPath',
				type: 'string',
				default: '',
				required: true,
				description: 'Path to the object in the bucket',
			},
			{
				displayName: 'Expires (Seconds)',
				name: 'expires',
				type: 'number',
				default: 8400,
				required: true,
				description: 'Expiration time in seconds',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		// Get credentials once if they don't depend on items
		// Note: aws credentials usually return accessKeyId and secretAccessKey
		const credentials = await this.getCredentials('aws');
		const accessKeyId = credentials.accessKeyId as string;
		const secretAccessKey = credentials.secretAccessKey as string;
		const sessionToken = credentials.temporaryCredentials
			? (credentials.sessionToken as string)
			: undefined;

		if (!accessKeyId || !secretAccessKey) {
			throw new NodeOperationError(
				this.getNode(),
				'AWS credentials must include Access Key ID and Secret Access Key. "Assume Role" is not supported by this node implementation.',
			);
		}

		for (let i = 0; i < items.length; i++) {
			try {
				const bucketName = this.getNodeParameter('bucketName', i) as string;
				let region = this.getNodeParameter('region', i) as string;
				const objectPath = this.getNodeParameter('objectPath', i) as string;
				const expires = this.getNodeParameter('expires', i) as number;

				if (!region) {
					region = credentials.region as string;
				}

				const url = awsS3PresignDownload(
					accessKeyId,
					secretAccessKey,
					bucketName,
					region || 'us-east-1',
					objectPath,
					expires,
					sessionToken,
				);

				returnData.push({
					json: {
						url,
					},
					pairedItem: {
						item: i,
					},
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error.message,
						},
						pairedItem: {
							item: i,
						},
					});
					continue;
				}
				throw error;
			}
		}

		return [returnData];
	}
}

function awsS3PresignDownload(
	accessKeyId: string,
	secretAccessKey: string,
	bucketName: string,
	region: string,
	objectPath: string,
	expires: number = 8400,
	sessionToken?: string,
): string {
	// Ensure the object path starts with a slash and is only encoded once
	const canonicalUri = '/' + objectPath.replace(/^\/+/, '');
	const encodedUri = encodeURIComponent(canonicalUri).replace(/%2F/g, '/');

	const host = `s3.amazonaws.com`; // assuming path-style like: s3.cubbit.eu/bucket/key or s3.amazonaws.com/bucket/key
	const headerString = `host:${host}\n`;
	const signedHeaders = 'host';

	// Real UTC timestamp
	const now = new Date();
	const pad = (n: number) => n.toString().padStart(2, '0');
	const dateText =
		now.getUTCFullYear().toString() + pad(now.getUTCMonth() + 1) + pad(now.getUTCDate());
	const timeText =
		dateText +
		'T' +
		pad(now.getUTCHours()) +
		pad(now.getUTCMinutes()) +
		pad(now.getUTCSeconds()) +
		'Z';

	const algorithm = 'AWS4-HMAC-SHA256';
	const scope = `${dateText}/${region}/s3/aws4_request`;

	const xAmzParams: Record<string, string> = {
		'X-Amz-Algorithm': algorithm,
		'X-Amz-Credential': `${accessKeyId}/${scope}`,
		'X-Amz-Date': timeText,
		'X-Amz-SignedHeaders': signedHeaders,
	};

	if (sessionToken) {
		xAmzParams['X-Amz-Security-Token'] = sessionToken;
	}

	if (expires > 0) {
		xAmzParams['X-Amz-Expires'] = expires.toString();
	}

	const sortedKeys = Object.keys(xAmzParams).sort();
	const queryString = sortedKeys
		.map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(xAmzParams[key])}`)
		.join('&');

	// Full canonical URI includes /bucket/key for path-style
	const canonicalPath = `/${bucketName}${encodedUri}`;

	const canonicalRequest = [
		'GET',
		canonicalPath,
		queryString,
		headerString,
		signedHeaders,
		'UNSIGNED-PAYLOAD',
	].join('\n');

	const hashedCanonicalRequest = crypto
		.createHash('sha256')
		.update(canonicalRequest, 'utf8')
		.digest('hex');
	const stringToSign = `${algorithm}\n${timeText}\n${scope}\n${hashedCanonicalRequest}`;

	const hmac = (key: string | Buffer, data: string) =>
		crypto.createHmac('sha256', key).update(data, 'utf8').digest();
	const dateKey = hmac(`AWS4${secretAccessKey}`, dateText);
	const dateRegionKey = hmac(dateKey, region);
	const dateServiceKey = hmac(dateRegionKey, 's3');
	const signingKey = hmac(dateServiceKey, 'aws4_request');

	const signature = crypto
		.createHmac('sha256', signingKey)
		.update(stringToSign, 'utf8')
		.digest('hex');

	// Final URL (path-style)
	return `https://${host}/${bucketName}${encodedUri}?${queryString}&X-Amz-Signature=${signature}`;
}
