/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Raw } from '@vscode/prompt-tsx';
import { beforeEach, describe, expect, it } from 'vitest';
import { ConfigKey } from '../../../configuration/common/configurationService';
import { DefaultsOnlyConfigurationService } from '../../../configuration/common/defaultsOnlyConfigurationService';
import { InMemoryConfigurationService } from '../../../configuration/test/common/inMemoryConfigurationService';
import { TestLogService } from '../../../testing/common/testLogService';
import {
	BUILT_IN_PATTERNS,
	extractTextFromMessages,
	getUniqueCategories,
	NullSensitiveDataFilterService,
} from '../../common/sensitiveDataFilterService';
import { SensitiveDataFilterService } from '../../node/sensitiveDataFilterServiceImpl';

const { SensitiveDataFilter } = ConfigKey;

describe('SensitiveDataFilterService', () => {
	let service: SensitiveDataFilterService;
	let configService: InMemoryConfigurationService;
	let logService: TestLogService;

	beforeEach(() => {
		configService = new InMemoryConfigurationService(new DefaultsOnlyConfigurationService(), new Map(), new Map());
		logService = new TestLogService();
		// Enable the service by default for tests
		configService.setConfig(SensitiveDataFilter.Enabled, true);
		service = new SensitiveDataFilterService(configService, logService);
	});

	describe('isEnabled', () => {
		it('should return true when enabled in config', () => {
			configService.setConfig(SensitiveDataFilter.Enabled, true);
			expect(service.isEnabled()).toBe(true);
		});

		it('should return false when disabled in config', () => {
			configService.setConfig(SensitiveDataFilter.Enabled, false);
			expect(service.isEnabled()).toBe(false);
		});
	});

	describe('checkForSensitiveData', () => {
		it('should return empty array when disabled', async () => {
			configService.setConfig(SensitiveDataFilter.Enabled, false);
			const text = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz12';
			const matches = await service.checkForSensitiveData(text);
			expect(matches).toEqual([]);
		});

		it('should detect GitHub personal access token', async () => {
			const text = 'Here is my token: ghp_1234567890abcdefghijklmnopqrstuvwxyz12';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'API Key')).toBe(true);
		});

		it('should detect GitHub OAuth token', async () => {
			const text = 'Token: gho_1234567890abcdefghijklmnopqrstuvwxyz12';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'API Key')).toBe(true);
		});

		it('should detect AWS access key', async () => {
			const text = 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'AWS Credentials')).toBe(true);
		});

		it('should detect AWS secret key', async () => {
			const text = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'AWS Credentials')).toBe(true);
		});

		it('should detect password in configuration', async () => {
			const text = 'password="MySecretPassword123!"';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'Password')).toBe(true);
		});

		it('should detect PEM private key header', async () => {
			const text = '-----BEGIN RSA PRIVATE KEY-----';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'Private Key')).toBe(true);
		});

		it('should detect SSH private key', async () => {
			const text = '-----BEGIN OPENSSH PRIVATE KEY-----';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'Private Key')).toBe(true);
		});

		it('should detect social security number', async () => {
			const text = 'My SSN is 123-45-6789';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'SSN')).toBe(true);
		});

		it('should detect credit card number', async () => {
			const text = 'Card number: 4111111111111111';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'Credit Card')).toBe(true);
		});

		it('should detect database connection string', async () => {
			const text = 'mongodb://user:pass@localhost:27017/mydb';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'Connection String')).toBe(true);
		});

		it('should detect SQL Server connection string', async () => {
			// Test with a JDBC-style connection string that our pattern matches
			const text = 'jdbc:mysql://localhost:3306/mydb;user=admin;password=secret123';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'Connection String')).toBe(true);
		});

		it('should detect private IPv4 addresses', async () => {
			const text = 'Connect to server at 192.168.1.100';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'IP Address')).toBe(true);
		});

		it('should detect IPv4 address in class A private range', async () => {
			const text = 'Server: 10.0.0.50';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'IP Address')).toBe(true);
		});

		it('should also detect public IP addresses', async () => {
			const text = 'Public server: 8.8.8.8';
			const matches = await service.checkForSensitiveData(text);
			// The ipv4-address pattern should match ALL IP addresses including public ones
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'IP Address')).toBe(true);
		});

		it('should detect IP address in question format like "What is 1.2.3.4?"', async () => {
			const text = 'What is 1.2.3.4?';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.category === 'IP Address')).toBe(true);
			expect(matches.some(m => m.patternName === 'ipv4-address')).toBe(true);
		});

		it('should detect multiple patterns in text', async () => {
			const text = `
				password="secret123"
				AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
				ghp_1234567890abcdefghijklmnopqrstuvwxyz12
			`;
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(2);
			const categories = new Set(matches.map(m => m.category));
			expect(categories.has('Password')).toBe(true);
			expect(categories.has('AWS Credentials')).toBe(true);
			expect(categories.has('API Key')).toBe(true);
		});

		it('should return empty array for clean text', async () => {
			const text = 'This is a normal message without any sensitive data.';
			const matches = await service.checkForSensitiveData(text);
			expect(matches).toEqual([]);
		});
	});

	describe('custom patterns', () => {
		it('should use custom patterns when configured', async () => {
			configService.setConfig(SensitiveDataFilter.CustomPatterns, [
				{ name: 'Custom Secret', category: 'Custom', pattern: 'MY_CUSTOM_SECRET_[A-Z0-9]+' },
			]);
			service.invalidateCache();

			const text = 'Here is MY_CUSTOM_SECRET_ABC123XYZ';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.length).toBeGreaterThan(0);
			expect(matches.some(m => m.patternName === 'Custom Secret')).toBe(true);
			expect(matches.some(m => m.category === 'Custom')).toBe(true);
		});

		it('should combine built-in and custom patterns', async () => {
			configService.setConfig(SensitiveDataFilter.UseBuiltInPatterns, true);
			configService.setConfig(SensitiveDataFilter.CustomPatterns, [
				{ name: 'Custom Secret', category: 'Custom', pattern: 'CUSTOM_[A-Z]+' },
			]);
			service.invalidateCache();

			const text = 'CUSTOM_SECRET and ghp_1234567890abcdefghijklmnopqrstuvwxyz12';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.some(m => m.category === 'Custom')).toBe(true);
			expect(matches.some(m => m.category === 'API Key')).toBe(true);
		});

		it('should use only custom patterns when built-in disabled', async () => {
			configService.setConfig(SensitiveDataFilter.UseBuiltInPatterns, false);
			configService.setConfig(SensitiveDataFilter.CustomPatterns, [
				{ name: 'Custom Secret', category: 'Custom', pattern: 'CUSTOM_[A-Z]+' },
			]);
			service.invalidateCache();

			const text = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz12';
			const matches = await service.checkForSensitiveData(text);
			// Should not detect GitHub token since built-in patterns are disabled
			expect(matches.every(m => m.category !== 'API Key')).toBe(true);
		});

		it('should skip invalid regex patterns gracefully', async () => {
			configService.setConfig(SensitiveDataFilter.CustomPatterns, [
				{ name: 'Invalid Pattern', category: 'Custom', pattern: '[invalid(regex' },
				{ name: 'Valid Pattern', category: 'Custom', pattern: 'VALID_[A-Z]+' },
			]);
			service.invalidateCache();

			const text = 'VALID_ABC';
			const matches = await service.checkForSensitiveData(text);
			expect(matches.some(m => m.patternName === 'Valid Pattern')).toBe(true);
		});
	});

	describe('cache invalidation', () => {
		it('should update patterns after cache invalidation', async () => {
			configService.setConfig(SensitiveDataFilter.CustomPatterns, [
				{ name: 'Pattern 1', category: 'Test', pattern: 'PATTERN1_[A-Z]+' },
			]);
			service.invalidateCache();

			let matches = await service.checkForSensitiveData('PATTERN1_ABC');
			expect(matches.some(m => m.patternName === 'Pattern 1')).toBe(true);

			configService.setConfig(SensitiveDataFilter.CustomPatterns, [
				{ name: 'Pattern 2', category: 'Test', pattern: 'PATTERN2_[A-Z]+' },
			]);
			service.invalidateCache();

			matches = await service.checkForSensitiveData('PATTERN1_ABC');
			expect(matches.every(m => m.patternName !== 'Pattern 1')).toBe(true);

			matches = await service.checkForSensitiveData('PATTERN2_ABC');
			expect(matches.some(m => m.patternName === 'Pattern 2')).toBe(true);
		});
	});
});

describe('extractTextFromMessages', () => {
	it('should extract text from simple string content', () => {
		const messages = [
			{ content: 'Hello, world!' },
			{ content: 'This is a test.' },
		];
		const text = extractTextFromMessages(messages);
		expect(text).toContain('Hello, world!');
		expect(text).toContain('This is a test.');
	});

	it('should extract text from array content', () => {
		const messages = [
			{
				content: [
					{ type: 'text', text: 'First part' },
					{ type: 'text', text: 'Second part' },
				],
			},
		];
		const text = extractTextFromMessages(messages);
		expect(text).toContain('First part');
		expect(text).toContain('Second part');
	});

	it('should extract text from tool calls', () => {
		const messages = [
			{
				content: 'Message content',
				toolCalls: [
					{ function: { arguments: '{"key": "value"}' } },
				],
			},
		];
		const text = extractTextFromMessages(messages);
		expect(text).toContain('Message content');
		expect(text).toContain('{"key": "value"}');
	});

	it('should handle mixed content types', () => {
		const messages = [
			{ content: 'Simple string' },
			{
				content: [
					{ type: 'text', text: 'Array text' },
					{ type: 'image', url: 'http://example.com/image.png' },
				],
			},
			{
				content: 'With tool call',
				toolCalls: [
					{ function: { arguments: 'arg1' } },
				],
			},
		];
		const text = extractTextFromMessages(messages);
		expect(text).toContain('Simple string');
		expect(text).toContain('Array text');
		expect(text).toContain('With tool call');
		expect(text).toContain('arg1');
	});

	it('should handle empty messages', () => {
		const text = extractTextFromMessages([]);
		expect(text).toBe('');
	});

	it('should extract text from Raw.ChatMessage format with ChatCompletionContentPartKind.Text', () => {
		// This is the format used in the actual chat endpoint
		const messages = [
			{
				role: Raw.ChatRole.User,
				content: [
					{ type: Raw.ChatCompletionContentPartKind.Text, text: 'What is 1.2.3.4?' }
				]
			}
		];
		const text = extractTextFromMessages(messages as any);
		expect(text).toContain('What is 1.2.3.4?');
	});

	it('should extract text from Raw.ChatMessage with string content', () => {
		// Some message formats use string content directly
		const messages = [
			{
				role: Raw.ChatRole.User,
				content: 'What is 1.2.3.4?'
			}
		];
		const text = extractTextFromMessages(messages as any);
		expect(text).toContain('What is 1.2.3.4?');
	});
});

describe('getUniqueCategories', () => {
	it('should return unique categories', () => {
		const matches = [
			{ patternName: 'Pattern 1', category: 'API Key' },
			{ patternName: 'Pattern 2', category: 'Password' },
			{ patternName: 'Pattern 3', category: 'API Key' },
		];
		const categories = getUniqueCategories(matches);
		expect(categories).toHaveLength(2);
		expect(categories).toContain('API Key');
		expect(categories).toContain('Password');
	});

	it('should return empty array for empty matches', () => {
		const categories = getUniqueCategories([]);
		expect(categories).toEqual([]);
	});
});

describe('NullSensitiveDataFilterService', () => {
	it('should always return false for isEnabled', () => {
		expect(NullSensitiveDataFilterService.Instance.isEnabled()).toBe(false);
	});

	it('should always return empty array for checkForSensitiveData', async () => {
		const matches = await NullSensitiveDataFilterService.Instance.checkForSensitiveData('ghp_secret');
		expect(matches).toEqual([]);
	});

	it('should do nothing for invalidateCache', () => {
		// Should not throw
		expect(() => NullSensitiveDataFilterService.Instance.invalidateCache()).not.toThrow();
	});
});

describe('BUILT_IN_PATTERNS', () => {
	it('should have patterns for all major categories', () => {
		const categories = new Set(BUILT_IN_PATTERNS.map(p => p.category));
		expect(categories.has('API Key')).toBe(true);
		expect(categories.has('AWS Credentials')).toBe(true);
		expect(categories.has('Password')).toBe(true);
		expect(categories.has('Private Key')).toBe(true);
		expect(categories.has('SSN')).toBe(true);
		expect(categories.has('Credit Card')).toBe(true);
		expect(categories.has('Connection String')).toBe(true);
		expect(categories.has('IP Address')).toBe(true);
	});

	it('should have valid regex patterns', () => {
		for (const pattern of BUILT_IN_PATTERNS) {
			expect(() => new RegExp(pattern.pattern, 'gi')).not.toThrow();
		}
	});
});
