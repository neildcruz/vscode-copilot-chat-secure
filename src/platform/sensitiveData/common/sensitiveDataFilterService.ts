/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Raw } from '@vscode/prompt-tsx';
import { createServiceIdentifier } from '../../../util/common/services';

/**
 * Represents a match of sensitive data found in text
 */
export interface SensitiveDataMatch {
	/** The category of sensitive data (e.g., "API Key", "Password") */
	category: string;
	/** The specific pattern name that matched */
	patternName: string;
}

/**
 * Definition of a sensitive data pattern
 */
export interface SensitiveDataPattern {
	/** Unique name for the pattern */
	name: string;
	/** Category for grouping patterns (shown in error messages) */
	category: string;
	/** Regular expression pattern string */
	pattern: string;
}

/**
 * Built-in sensitive data patterns organized by category
 */
export const BUILT_IN_PATTERNS: readonly SensitiveDataPattern[] = [
	// API Keys
	{
		name: 'generic-api-key',
		category: 'API Key',
		pattern: '(?:api[_-]?key|apikey)\\s*[:=]\\s*[\'"]?[\\w-]{20,}[\'"]?',
	},
	{
		name: 'github-token',
		category: 'API Key',
		pattern: 'gh[pousr]_[A-Za-z0-9_]{36,}',
	},
	{
		name: 'github-fine-grained-token',
		category: 'API Key',
		pattern: 'github_pat_[A-Za-z0-9_]{22,}',
	},

	// AWS Credentials
	{
		name: 'aws-access-key-id',
		category: 'AWS Credentials',
		pattern: '(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
	},
	{
		name: 'aws-secret-access-key',
		category: 'AWS Credentials',
		pattern: '(?:aws_secret_access_key|aws_secret_key)\\s*[:=]\\s*[\'"]?[A-Za-z0-9/+=]{40}[\'"]?',
	},

	// Passwords
	{
		name: 'password-assignment',
		category: 'Password',
		pattern: '(?:password|passwd|pwd)\\s*[:=]\\s*[\'"][^\'"]{8,}[\'"]',
	},

	// Private Keys
	{
		name: 'private-key-rsa',
		category: 'Private Key',
		pattern: '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
	},
	{
		name: 'private-key-pgp',
		category: 'Private Key',
		pattern: '-----BEGIN PGP PRIVATE KEY BLOCK-----',
	},

	// Social Security Numbers (US)
	{
		name: 'ssn-us',
		category: 'SSN',
		pattern: '\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b',
	},

	// Credit Card Numbers
	{
		name: 'credit-card-visa',
		category: 'Credit Card',
		pattern: '\\b4[0-9]{12}(?:[0-9]{3})?\\b',
	},
	{
		name: 'credit-card-mastercard',
		category: 'Credit Card',
		pattern: '\\b5[1-5][0-9]{14}\\b',
	},
	{
		name: 'credit-card-amex',
		category: 'Credit Card',
		pattern: '\\b3[47][0-9]{13}\\b',
	},
	{
		name: 'credit-card-discover',
		category: 'Credit Card',
		pattern: '\\b6(?:011|5[0-9]{2})[0-9]{12}\\b',
	},

	// Connection Strings
	{
		name: 'connection-string-generic',
		category: 'Connection String',
		pattern: '(?:mongodb(?:\\+srv)?|postgres|mysql|mssql|redis):\\/\\/[^\\s]+:[^\\s]+@[^\\s]+',
	},
	{
		name: 'connection-string-jdbc',
		category: 'Connection String',
		pattern: 'jdbc:[a-z]+:\\/\\/[^\\s]+;(?:user|password)=[^\\s;]+',
	},

	// IP Addresses
	{
		name: 'ipv4-address',
		category: 'IP Address',
		pattern: '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b',
	},
	{
		name: 'ipv6-address',
		category: 'IP Address',
		pattern: '\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b|\\b(?:[0-9a-fA-F]{1,4}:){1,7}:\\b|\\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\\b',
	},

	// Email Addresses
	{
		name: 'email-address',
		category: 'Email Address',
		pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b',
	},
];

/**
 * Service for detecting sensitive data in text content before sending to Copilot APIs
 */
export const ISensitiveDataFilterService = createServiceIdentifier<ISensitiveDataFilterService>('ISensitiveDataFilterService');

export interface ISensitiveDataFilterService {
	readonly _serviceBrand: undefined;

	/**
	 * Check text for sensitive data patterns
	 * @param text The text to scan
	 * @returns Array of matches found, empty if no sensitive data detected
	 */
	checkForSensitiveData(text: string): Promise<SensitiveDataMatch[]>;

	/**
	 * Check if the sensitive data filter is enabled
	 */
	isEnabled(): boolean;

	/**
	 * Get all active patterns (built-in + custom)
	 */
	getActivePatterns(): SensitiveDataPattern[];

	/**
	 * Invalidate the compiled pattern cache (called on configuration change)
	 */
	invalidateCache(): void;
}

/**
 * Generic chat message type for text extraction
 * Compatible with Raw.ChatMessage from prompt-tsx
 */
interface ChatMessageLike {
	content: string | { type: string | number; text?: string }[];
	toolCalls?: { function?: { arguments?: string } }[];
}

/**
 * Extract all text content from chat messages for scanning
 */
export function extractTextFromMessages(messages: ChatMessageLike[]): string {
	const textParts: string[] = [];

	for (const message of messages) {
		// Handle string content directly
		if (typeof message.content === 'string') {
			textParts.push(message.content);
		} else if (Array.isArray(message.content)) {
			// Handle array of content parts
			for (const part of message.content) {
				// Check for both string 'text' and numeric enum Raw.ChatCompletionContentPartKind.Text (which is 1)
				if ((part.type === 'text' || part.type === Raw.ChatCompletionContentPartKind.Text) && part.text) {
					textParts.push(part.text);
				}
			}
		}

		// Include tool call arguments if present
		if (message.toolCalls) {
			for (const toolCall of message.toolCalls) {
				if (toolCall.function?.arguments) {
					textParts.push(toolCall.function.arguments);
				}
			}
		}
	}

	return textParts.join('\n');
}

/**
 * Get unique categories from an array of matches
 */
export function getUniqueCategories(matches: SensitiveDataMatch[]): string[] {
	const categories = new Set<string>();
	for (const match of matches) {
		categories.add(match.category);
	}
	return Array.from(categories).sort();
}

/**
 * Null implementation for environments where filtering is not needed
 */
export class NullSensitiveDataFilterService implements ISensitiveDataFilterService {
	readonly _serviceBrand: undefined;

	static readonly Instance = new NullSensitiveDataFilterService();

	async checkForSensitiveData(_text: string): Promise<SensitiveDataMatch[]> {
		return [];
	}

	isEnabled(): boolean {
		return false;
	}

	getActivePatterns(): SensitiveDataPattern[] {
		return [];
	}

	invalidateCache(): void {
		// No-op
	}
}
