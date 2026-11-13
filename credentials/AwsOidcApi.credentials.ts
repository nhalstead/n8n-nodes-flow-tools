import type {
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IHttpRequestOptions,
	INodeProperties,
} from 'n8n-workflow';
import { UserError } from 'n8n-workflow';

import { resolveAwsOidcTemporaryCredentials } from './awsOidc/credential-cache';
import { type AwsOidcCredentials, signAwsRequest } from './awsOidc/utils';

export class AwsOidcApi implements ICredentialType {
	name = 'awsOidcApi';

	displayName = 'AWS OIDC API';

	documentationUrl =
		'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html';

	icon = { light: 'file:awsOidc.svg', dark: 'file:awsOidc.dark.svg' } as const;

	properties: INodeProperties[] = [
		{
			displayName:
				'Exchanges OAuth2 client credentials for an OIDC JWT, then calls STS AssumeRoleWithWebIdentity for temporary AWS session credentials.',
			name: 'notice',
			type: 'notice',
			default: '',
		},
		{
			displayName: 'Region',
			name: 'region',
			type: 'string',
			default: 'us-east-1',
			required: true,
			placeholder: 'us-east-1',
			description: 'AWS region used for the STS endpoint and request signing',
		},
		{
			displayName: 'Access Token URL',
			name: 'accessTokenUrl',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'https://login.example.com/oauth/token',
			description: 'OAuth2 / OIDC token endpoint (client credentials grant)',
		},
		{
			displayName: 'Client ID',
			name: 'clientId',
			type: 'string',
			default: '',
			required: true,
		},
		{
			displayName: 'Client Secret',
			name: 'clientSecret',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
		},
		{
			displayName: 'Scope',
			name: 'scope',
			type: 'string',
			default: '',
			description: 'Optional OAuth2 scope (e.g. openid). Sent as the scope body parameter.',
		},
		{
			displayName: 'Audience',
			name: 'audience',
			type: 'string',
			default: '',
			placeholder: 'aws-sts',
			description:
				'Optional OAuth2 audience body parameter. Use when the IdP needs it to mint a JWT whose aud claim matches your IAM role trust policy. Leave empty if the IdP already sets aud (often to the client ID).',
		},
		{
			displayName: 'Resource',
			name: 'resource',
			type: 'string',
			default: '',
			description:
				'Optional OAuth2 resource indicator (RFC 8707). Some IdPs use resource instead of (or in addition to) audience.',
		},
		{
			displayName: 'Authentication',
			name: 'authentication',
			type: 'options',
			options: [
				{
					name: 'Header',
					value: 'header',
					description: 'Send client credentials as a Basic Auth header',
				},
				{
					name: 'Body',
					value: 'body',
					description: 'Send client credentials in the request body',
				},
			],
			default: 'header',
		},
		{
			displayName: 'Token Property',
			name: 'tokenProperty',
			type: 'options',
			options: [
				{
					name: 'Access Token',
					value: 'access_token',
					description:
						'Use access_token (must be a JWT). Opaque access tokens fail STS with "not a valid JWT".',
				},
				{
					name: 'ID Token',
					value: 'id_token',
					description:
						'Use id_token. Preferred for OIDC; may require including "openid" in Scope.',
				},
			],
			default: 'id_token',
			description:
				'Which token response field to send to STS as WebIdentityToken. STS requires a JWT.',
		},
		{
			displayName: 'Role ARN',
			name: 'roleArn',
			type: 'string',
			default: '',
			required: true,
			placeholder: 'arn:aws:iam::123456789012:role/MyOidcRole',
			description: 'IAM role to assume via AssumeRoleWithWebIdentity',
		},
		{
			displayName: 'Role Session Name',
			name: 'roleSessionName',
			type: 'string',
			default: 'n8n-oidc-session',
			required: true,
			description: 'Name for the assumed-role session (appears in CloudTrail)',
		},
		{
			displayName: 'Duration Seconds',
			name: 'durationSeconds',
			type: 'number',
			default: 3600,
			description:
				'Lifetime of the temporary credentials in seconds. Leave at the default unless your role allows a different max session duration.',
			typeOptions: {
				minValue: 900,
				maxValue: 43200,
			},
		},
	];

	async authenticate(
		rawCredentials: ICredentialDataDecryptedObject,
		requestOptions: IHttpRequestOptions,
	): Promise<IHttpRequestOptions> {
		const credentials = rawCredentials as unknown as AwsOidcCredentials;
		const region = (credentials.region || 'us-east-1').trim();

		let securityHeaders;
		try {
			securityHeaders = await resolveAwsOidcTemporaryCredentials(credentials);
		} catch (error) {
			const message = error instanceof Error ? error.message : 'Unknown error';
			throw new UserError(`AWS OIDC authentication failed: ${message}`);
		}

		const service =
			typeof requestOptions.qs?.service === 'string' ? requestOptions.qs.service : 'sts';

		if (requestOptions.qs) {
			const { service: _service, ...restQs } = requestOptions.qs;
			requestOptions.qs = Object.keys(restQs).length ? restQs : undefined;
		}

		return signAwsRequest(requestOptions, securityHeaders, region, service);
	}

	test: ICredentialTestRequest = {
		request: {
			baseURL:
				'={{$credentials.region.startsWith("cn-") ? `https://sts.${$credentials.region}.amazonaws.com.cn` : `https://sts.${$credentials.region}.amazonaws.com`}}',
			url: '?Action=GetCallerIdentity&Version=2011-06-15',
			method: 'POST',
			headers: {
				Accept: 'application/json',
			},
		},
	};
}
