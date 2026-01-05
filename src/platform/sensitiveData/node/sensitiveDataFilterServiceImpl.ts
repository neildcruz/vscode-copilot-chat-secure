/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Disposable } from '../../../util/vs/base/common/lifecycle';
import { ConfigKey, IConfigurationService } from '../../configuration/common/configurationService';
import { ILogService } from '../../log/common/logService';
import {
	BUILT_IN_PATTERNS,
	ISensitiveDataFilterService,
	SensitiveDataMatch,
	SensitiveDataPattern,
} from '../common/sensitiveDataFilterService';

/**
 * Compiled pattern with its metadata
 */
interface CompiledPattern {
	regex: RegExp;
	name: string;
	category: string;
}

/**
 * Chunk size for async processing of large text inputs
 * Process in 50KB chunks to avoid blocking the event loop
 */
const CHUNK_SIZE = 50 * 1024;

/**
 * Node.js implementation of the sensitive data filter service
 */
export class SensitiveDataFilterService extends Disposable implements ISensitiveDataFilterService {
	declare readonly _serviceBrand: undefined;

	private _compiledPatterns: CompiledPattern[] | undefined;
	private _activePatterns: SensitiveDataPattern[] | undefined;

	constructor(
		@IConfigurationService private readonly _configurationService: IConfigurationService,
		@ILogService private readonly _logService: ILogService,
	) {
		super();

		// Listen for configuration changes to invalidate cache
		this._register(this._configurationService.onDidChangeConfiguration(e => {
			if (e.affectsConfiguration(ConfigKey.SensitiveDataFilter.Enabled.fullyQualifiedId) ||
				e.affectsConfiguration(ConfigKey.SensitiveDataFilter.CustomPatterns.fullyQualifiedId) ||
				e.affectsConfiguration(ConfigKey.SensitiveDataFilter.UseBuiltInPatterns.fullyQualifiedId)) {
				this.invalidateCache();
			}
		}));
	}

	/**
	 * Check if the sensitive data filter is enabled
	 */
	isEnabled(): boolean {
		return this._configurationService.getConfig(ConfigKey.SensitiveDataFilter.Enabled);
	}

	/**
	 * Get all active patterns (built-in + custom)
	 */
	getActivePatterns(): SensitiveDataPattern[] {
		if (this._activePatterns) {
			return this._activePatterns;
		}

		const patterns: SensitiveDataPattern[] = [];

		// Add built-in patterns if enabled
		const useBuiltIn = this._configurationService.getConfig(ConfigKey.SensitiveDataFilter.UseBuiltInPatterns);
		if (useBuiltIn) {
			patterns.push(...BUILT_IN_PATTERNS);
		}

		// Add custom patterns from configuration
		const customPatterns = this._configurationService.getConfig(ConfigKey.SensitiveDataFilter.CustomPatterns);
		if (customPatterns && Array.isArray(customPatterns)) {
			for (const custom of customPatterns) {
				if (custom.name && custom.category && custom.pattern) {
					patterns.push({
						name: custom.name,
						category: custom.category,
						pattern: custom.pattern,
					});
				}
			}
		}

		this._activePatterns = patterns;
		return patterns;
	}

	/**
	 * Get compiled regex patterns, creating them if needed
	 */
	private _getCompiledPatterns(): CompiledPattern[] {
		if (this._compiledPatterns) {
			return this._compiledPatterns;
		}

		const patterns = this.getActivePatterns();
		this._compiledPatterns = [];

		for (const pattern of patterns) {
			try {
				const regex = new RegExp(pattern.pattern, 'gi');
				this._compiledPatterns.push({
					regex,
					name: pattern.name,
					category: pattern.category,
				});
			} catch {
				// Skip invalid regex patterns silently
			}
		}

		return this._compiledPatterns;
	}

	/**
	 * Invalidate the compiled pattern cache
	 */
	invalidateCache(): void {
		this._compiledPatterns = undefined;
		this._activePatterns = undefined;
	}

	/**
	 * Check text for sensitive data patterns
	 * Uses async chunking for large inputs to avoid blocking the event loop
	 */
	async checkForSensitiveData(text: string): Promise<SensitiveDataMatch[]> {
		const enabled = this.isEnabled();
		this._logService.trace(`[SensitiveDataFilter] checkForSensitiveData called. enabled=${enabled}, textLength=${text.length}`);

		if (!enabled) {
			this._logService.trace(`[SensitiveDataFilter] Filter is disabled, skipping check`);
			return [];
		}

		const compiledPatterns = this._getCompiledPatterns();
		this._logService.trace(`[SensitiveDataFilter] Got ${compiledPatterns.length} compiled patterns`);

		if (compiledPatterns.length === 0) {
			return [];
		}

		// For small texts, process synchronously
		if (text.length <= CHUNK_SIZE) {
			const matches = this._checkTextSync(text, compiledPatterns);
			this._logService.trace(`[SensitiveDataFilter] Found ${matches.length} matches`);
			return matches;
		}

		// For large texts, process in chunks asynchronously
		return this._checkTextAsync(text, compiledPatterns);
	}

	/**
	 * Synchronous check for small text inputs
	 */
	private _checkTextSync(text: string, patterns: CompiledPattern[]): SensitiveDataMatch[] {
		const matches: SensitiveDataMatch[] = [];
		const seenPatterns = new Set<string>();

		for (const pattern of patterns) {
			// Reset regex state for global patterns
			pattern.regex.lastIndex = 0;

			if (pattern.regex.test(text) && !seenPatterns.has(pattern.name)) {
				seenPatterns.add(pattern.name);
				matches.push({
					category: pattern.category,
					patternName: pattern.name,
				});
			}
		}

		return matches;
	}

	/**
	 * Async check for large text inputs, processing in chunks
	 */
	private async _checkTextAsync(text: string, patterns: CompiledPattern[]): Promise<SensitiveDataMatch[]> {
		const matches: SensitiveDataMatch[] = [];
		const seenPatterns = new Set<string>();

		// Process each pattern across the full text, yielding between patterns
		for (const pattern of patterns) {
			if (seenPatterns.has(pattern.name)) {
				continue;
			}

			// Reset regex state
			pattern.regex.lastIndex = 0;

			// Check text in chunks with overlap to catch patterns spanning chunk boundaries
			const overlap = 100; // Overlap to catch patterns at boundaries
			let offset = 0;

			while (offset < text.length) {
				const end = Math.min(offset + CHUNK_SIZE + overlap, text.length);
				const chunk = text.slice(offset, end);

				// Reset and test
				pattern.regex.lastIndex = 0;
				if (pattern.regex.test(chunk)) {
					seenPatterns.add(pattern.name);
					matches.push({
						category: pattern.category,
						patternName: pattern.name,
					});
					break; // Found a match for this pattern, move to next
				}

				offset += CHUNK_SIZE;

				// Yield to event loop periodically
				if (offset < text.length) {
					await this._yieldToEventLoop();
				}
			}
		}

		return matches;
	}

	/**
	 * Yield to the event loop to prevent blocking
	 */
	private _yieldToEventLoop(): Promise<void> {
		return new Promise(resolve => setTimeout(resolve, 0));
	}
}
