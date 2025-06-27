/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getOauthClient } from './oauth2.js';
import { OAuth2Client } from 'google-auth-library';
import * as fs from 'fs';
import * as path from 'path';
import http from 'http';
import open from 'open';
import crypto from 'crypto';
import * as os from 'os';

vi.mock('os', async (importOriginal) => {
  const os = await importOriginal<typeof import('os')>();
  return {
    ...os,
    homedir: vi.fn(),
  };
});

vi.mock('google-auth-library');
vi.mock('http');
vi.mock('open');
vi.mock('crypto');
vi.mock('console', () => ({
  log: vi.fn(),
  error: vi.fn(),
}));

describe('oauth2', () => {
  let tempHomeDir: string;

  beforeEach(() => {
    tempHomeDir = fs.mkdtempSync(
      path.join(os.tmpdir(), 'gemini-cli-test-home-'),
    );
    vi.mocked(os.homedir).mockReturnValue(tempHomeDir);
  });
  afterEach(() => {
    fs.rmSync(tempHomeDir, { recursive: true, force: true });
  });

  it('should perform a web login', async () => {
    const mockAuthUrl = 'https://example.com/auth';
    const mockCode = 'test-code';
    const mockState = 'test-state';
    const mockTokens = {
      access_token: 'test-access-token',
      refresh_token: 'test-refresh-token',
    };

    const mockGenerateAuthUrl = vi.fn().mockReturnValue(mockAuthUrl);
    const mockGetToken = vi.fn().mockResolvedValue({ tokens: mockTokens });
    const mockSetCredentials = vi.fn();
    const mockOAuth2Client = {
      generateAuthUrl: mockGenerateAuthUrl,
      getToken: mockGetToken,
      setCredentials: mockSetCredentials,
      credentials: mockTokens,
    } as unknown as OAuth2Client;
    vi.mocked(OAuth2Client).mockImplementation(() => mockOAuth2Client);

    vi.spyOn(crypto, 'randomBytes').mockReturnValue(mockState as never);
    vi.mocked(open).mockImplementation(async () => ({}) as never);

    let requestCallback!: http.RequestListener<
      typeof http.IncomingMessage,
      typeof http.ServerResponse
    >;

    let serverListeningCallback: (value: unknown) => void;
    const serverListeningPromise = new Promise(
      (resolve) => (serverListeningCallback = resolve),
    );

    let capturedPort = 0;
    const mockHttpServer = {
      listen: vi.fn((port: number, callback?: () => void) => {
        capturedPort = port;
        if (callback) {
          callback();
        }
        serverListeningCallback(undefined);
      }),
      close: vi.fn((callback?: () => void) => {
        if (callback) {
          callback();
        }
      }),
      on: vi.fn(),
      address: () => ({ port: capturedPort }),
    };
    vi.mocked(http.createServer).mockImplementation((cb) => {
      requestCallback = cb as http.RequestListener<
        typeof http.IncomingMessage,
        typeof http.ServerResponse
      >;
      return mockHttpServer as unknown as http.Server;
    });

    const clientPromise = getOauthClient();

    // wait for server to start listening.
    await serverListeningPromise;

    const mockReq = {
      url: `/oauth2callback?code=${mockCode}&state=${mockState}`,
    } as http.IncomingMessage;
    const mockRes = {
      writeHead: vi.fn(),
      end: vi.fn(),
    } as unknown as http.ServerResponse;

    await requestCallback(mockReq, mockRes);

    const client = await clientPromise;
    expect(client).toBe(mockOAuth2Client);

    expect(open).toHaveBeenCalledWith(mockAuthUrl);
    expect(mockGetToken).toHaveBeenCalledWith({
      code: mockCode,
      redirect_uri: `http://localhost:${capturedPort}/oauth2callback`,
    });
    expect(mockSetCredentials).toHaveBeenCalledWith(mockTokens);

    const tokenPath = path.join(tempHomeDir, '.gemini', 'oauth_creds.json');
    const tokenData = JSON.parse(fs.readFileSync(tokenPath, 'utf-8'));
    expect(tokenData).toEqual(mockTokens);
  });

  it('should perform a device code login and succeed', async () => {
    const mockDeviceCodeResponse = {
      data: {
        device_code: 'test-device-code',
        user_code: 'TEST-USER-CODE',
        verification_url: 'https://example.com/device',
        expires_in: 1800, // 30 minutes
        interval: 1, // 1 second, to speed up test
      },
    };
    const mockTokens = {
      access_token: 'test-device-access-token',
      refresh_token: 'test-device-refresh-token',
    };

    const mockGetDeviceCode = vi.fn().mockResolvedValue(mockDeviceCodeResponse);
    const mockGetToken = vi
      .fn()
      .mockRejectedValueOnce({
        response: { data: { error: 'authorization_pending' } },
      }) // First poll: pending
      .mockResolvedValueOnce({ tokens: mockTokens }); // Second poll: success

    const mockSetCredentials = vi.fn();
    const mockOAuth2ClientInstance = {
      getDeviceCode: mockGetDeviceCode,
      getToken: mockGetToken,
      setCredentials: mockSetCredentials,
      credentials: mockTokens, // Simulate credentials being set
    } as unknown as OAuth2Client;

    vi.mocked(OAuth2Client).mockImplementation(
      () => mockOAuth2ClientInstance,
    );
    vi.spyOn(global, 'setTimeout').mockImplementation((fn) => {
      fn();
      return 0 as unknown as NodeJS.Timeout; // Return a dummy timeout ID
    });

    const client = await getOauthClient(true); // true for useDeviceCodeFlow

    expect(client).toBe(mockOAuth2ClientInstance);
    expect(mockGetDeviceCode).toHaveBeenCalledWith({
      scope: expect.any(String),
    });
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining(mockDeviceCodeResponse.data.verification_url),
    );
    expect(console.log).toHaveBeenCalledWith(
      expect.stringContaining(mockDeviceCodeResponse.data.user_code),
    );
    expect(mockGetToken).toHaveBeenCalledTimes(2);
    expect(mockSetCredentials).toHaveBeenCalledWith(mockTokens);
    expect(console.log).toHaveBeenCalledWith('Authentication successful!');

    // Verify credentials caching
    const tokenPath = path.join(tempHomeDir, '.gemini', 'oauth_creds.json');
    const tokenData = JSON.parse(fs.readFileSync(tokenPath, 'utf-8'));
    expect(tokenData).toEqual(mockTokens);

    // Restore setTimeout
    vi.mocked(global.setTimeout).mockRestore();
  });

  it('should handle device code login timeout', async () => {
    const mockDeviceCodeResponse = {
      data: {
        device_code: 'test-device-code-timeout',
        user_code: 'TEST-USER-CODE-TIMEOUT',
        verification_url: 'https://example.com/device_timeout',
        expires_in: 2, // Short expiry for testing timeout
        interval: 1, // 1 second interval
      },
    };

    const mockGetDeviceCode = vi.fn().mockResolvedValue(mockDeviceCodeResponse);
    // Always return pending until timeout
    const mockGetToken = vi
      .fn()
      .mockRejectedValue({
        response: { data: { error: 'authorization_pending' } },
      });

    const mockOAuth2ClientInstance = {
      getDeviceCode: mockGetDeviceCode,
      getToken: mockGetToken,
      setCredentials: vi.fn(),
    } as unknown as OAuth2Client;

    vi.mocked(OAuth2Client).mockImplementation(
      () => mockOAuth2ClientInstance,
    );
    vi.spyOn(global, 'setTimeout').mockImplementation((fn, timeout) => {
      // Call immediately for testing, but respect the "attempts" logic
      if (timeout && timeout > 0) {
        fn();
      }
      return 0 as unknown as NodeJS.Timeout;
    });

    await expect(getOauthClient(true)).rejects.toThrow(
      'Authentication timed out.',
    );

    expect(mockGetDeviceCode).toHaveBeenCalled();
    // Max attempts = expires_in / interval = 2 / 1 = 2. It polls, then tries again.
    // The first call is immediate due to the mock, subsequent calls are also immediate.
    // The check for maxAttempts happens *before* the API call.
    // So, it will attempt, increment, attempt, increment, then fail on the next check.
    expect(mockGetToken.mock.calls.length).toBeGreaterThanOrEqual(2);

    vi.mocked(global.setTimeout).mockRestore();
  });

  it('should handle device code login error (e.g. access_denied)', async () => {
    const mockDeviceCodeResponse = {
      data: {
        device_code: 'test-device-code-error',
        user_code: 'TEST-USER-CODE-ERROR',
        verification_url: 'https://example.com/device_error',
        expires_in: 1800,
        interval: 1,
      },
    };
    const mockError = {
      response: {
        data: { error: 'access_denied', error_description: 'User denied access' },
      },
    };

    const mockGetDeviceCode = vi.fn().mockResolvedValue(mockDeviceCodeResponse);
    const mockGetToken = vi.fn().mockRejectedValue(mockError);

    const mockOAuth2ClientInstance = {
      getDeviceCode: mockGetDeviceCode,
      getToken: mockGetToken,
      setCredentials: vi.fn(),
    } as unknown as OAuth2Client;

    vi.mocked(OAuth2Client).mockImplementation(
      () => mockOAuth2ClientInstance,
    );
    vi.spyOn(global, 'setTimeout').mockImplementation((fn) => {
      fn();
      return 0 as unknown as NodeJS.Timeout;
    });

    await expect(getOauthClient(true)).rejects.toThrow(
      'Error during authentication: User denied access',
    );

    expect(mockGetDeviceCode).toHaveBeenCalled();
    expect(mockGetToken).toHaveBeenCalledTimes(1);

    vi.mocked(global.setTimeout).mockRestore();
  });
});
