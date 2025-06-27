/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { OAuth2Client, Credentials } from 'google-auth-library';
import * as http from 'http';
import url from 'url';
import * as readline from 'readline';
import crypto from 'crypto';
import * as net from 'net';
import open from 'open';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import * as os from 'os';

//  OAuth Client ID used to initiate OAuth2Client class.
const OAUTH_CLIENT_ID =
  '681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com';

// OAuth Secret value used to initiate OAuth2Client class.
// Note: It's ok to save this in git because this is an installed application
// as described here: https://developers.google.com/identity/protocols/oauth2#installed
// "The process results in a client ID and, in some cases, a client secret,
// which you embed in the source code of your application. (In this context,
// the client secret is obviously not treated as a secret.)"
const OAUTH_CLIENT_SECRET = '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';

// OAuth Scopes for Cloud Code authorization.
const OAUTH_SCOPE = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

const HTTP_REDIRECT = 301;
const SIGN_IN_SUCCESS_URL =
  'https://developers.google.com/gemini-code-assist/auth_success_gemini';
const SIGN_IN_FAILURE_URL =
  'https://developers.google.com/gemini-code-assist/auth_failure_gemini';

const GEMINI_DIR = '.gemini';
const CREDENTIAL_FILENAME = 'oauth_creds.json';

/**
 * An Authentication URL for updating the credentials of a Oauth2Client
 * as well as a promise that will resolve when the credentials have
 * been refreshed (or which throws error when refreshing credentials failed).
 */

/**
 * Represents the state and necessary functions for a headless authentication step.
 * - `type`: Indicates the nature of the step, e.g., 'NEEDS_CODE'.
 * - `authUrl`: The URL the user needs to open in their browser.
 * - `exchangeCodeFunction`: A function that takes the user-provided code
 *   and completes the authentication, returning a Promise that resolves on
 *   success or rejects on error.
 */
export interface HeadlessAuthStep {
  type: 'NEEDS_CODE';
  authUrl: string;
  exchangeCodeFunction: (code: string) => Promise<void>;
}

export interface OauthWebLogin {
  authUrl: string; // For non-headless, this is the URL to open. For headless, it's also provided here and in headlessStep.
  loginCompletePromise: Promise<void>;
  headlessStep?: HeadlessAuthStep; // If present, CLI should use this for headless flow.
}

// Import Config type for the new parameter
import type { Config } from '../config/config.js';

export async function getOauthClient(config: Config): Promise<OAuth2Client> {
  const client = new OAuth2Client({
    clientId: OAUTH_CLIENT_ID,
    clientSecret: OAUTH_CLIENT_SECRET,
  });

  // Ensure headless step is cleared if not taking the authWithWeb path
  config.currentHeadlessAuthStep = undefined;

  if (await loadCachedCredentials(client)) {
    // Found valid cached credentials.
    return client;
  }

  const webLogin = await authWithWeb(client);
  config.currentHeadlessAuthStep = webLogin.headlessStep; // Set headlessStep on config

  // If not in headless mode (or if headless mode doesn't require special CLI handling before this point)
  // and webLogin.headlessStep is not set (or we decide CLI handles all headless messaging)
  if (!webLogin.headlessStep) {
    console.log(
      `\n\nCode Assist login required.\n` +
        `Attempting to open authentication page in your browser.\n` +
        `If the browser does not open, please navigate to:\n\n${webLogin.authUrl}\n\n`,
    );
    await open(webLogin.authUrl);
    console.log('Waiting for authentication...');
  } else {
    // For headless mode, the CLI will now use webLogin.headlessStep to provide instructions.
    // A generic "Waiting for authentication..." might still be applicable after CLI shows URL / prompts for code.
    // However, the actual prompt for code and URL display is deferred to the CLI.
    // We might want a different message here or let CLI handle all messages.
    // For now, let's assume CLI will show "Waiting for authentication..." if it needs to after its part.
    // Or, if the CLI immediately acts on headlessStep, this log might be shown *before* CLI prompts.
    // Let's refine this based on CLI behavior. For now, keeping a general waiting message.
    console.log('Authentication process initiated. Follow CLI prompts if in headless mode.');
  }

  await webLogin.loginCompletePromise;

  return client;
}

async function authWithWeb(client: OAuth2Client): Promise<OauthWebLogin> {
  const state = crypto.randomBytes(32).toString('hex');

  if (process.env.HEADLESS_LOGIN === 'true') {
    const redirectUri = 'urn:ietf:wg:oauth:2.0:oob';
    const authUrlString: string = client.generateAuthUrl({
      redirect_uri: redirectUri,
      access_type: 'offline',
      scope: OAUTH_SCOPE,
      state,
    });

    // For headless flow, the loginCompletePromise is controlled externally via exchangeCodeFunction
    let resolveLoginPromise: () => void;
    let rejectLoginPromise: (reason?: any) => void;
    const loginCompletePromise = new Promise<void>((resolve, reject) => {
      resolveLoginPromise = resolve;
      rejectLoginPromise = reject;
    });

    const exchangeCodeFunction = async (code: string): Promise<void> => {
      if (!code || code.trim() === '') {
        const err = new Error('No authorization code provided.');
        rejectLoginPromise(err);
        throw err;
      }
      try {
        const { tokens } = await client.getToken({
          code: code.trim(),
          redirect_uri: redirectUri, // Must match the one used in generateAuthUrl
        });
        client.setCredentials(tokens);
        await cacheCredentials(client.credentials);
        resolveLoginPromise();
      } catch (e) {
        const err = new Error(
          `Error exchanging authorization code: ${(e as Error).message}`,
        );
        rejectLoginPromise(err);
        throw err;
      }
    };

    return {
      authUrl: authUrlString,
      loginCompletePromise,
      headlessStep: {
        type: 'NEEDS_CODE',
        authUrl: authUrlString,
        exchangeCodeFunction,
      },
    };
  } else {
    //const port = await getAvailablePort();
    const port = 8081; // Using fixed port as in original code for now
    const redirectUri = `http://localhost:${port}/oauth2callback`;
    const authUrl: string = client.generateAuthUrl({
      redirect_uri: redirectUri,
      access_type: 'offline',
      scope: OAUTH_SCOPE,
      state,
    });

    const loginCompletePromise = new Promise<void>((resolve, reject) => {
      const server = http.createServer(async (req, res) => {
        try {
          if (!req.url || req.url.indexOf('/oauth2callback') === -1) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end();
            return reject(new Error('Unexpected request: ' + req.url));
          }
          const qs = new url.URL(
            req.url,
            `http://localhost:${port}`,
          ).searchParams;
          if (qs.get('error')) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end();
            return reject(
              new Error(`Error during authentication: ${qs.get('error')}`),
            );
          } else if (qs.get('state') !== state) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL }); // Or a specific error page
            res.end('State mismatch. Possible CSRF attack.');
            return reject(new Error('State mismatch. Possible CSRF attack.'));
          } else if (qs.get('code')) {
            const { tokens } = await client.getToken({
              code: qs.get('code')!,
              redirect_uri: redirectUri,
            });
            client.setCredentials(tokens);
            await cacheCredentials(client.credentials);

            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_SUCCESS_URL });
            res.end();
            resolve();
          } else {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end();
            reject(new Error('No code found in request'));
          }
        } catch (e) {
          // Ensure response is sent before rejecting if possible
          if (!res.headersSent) {
            res.writeHead(HTTP_REDIRECT, { Location: SIGN_IN_FAILURE_URL });
            res.end();
          }
          reject(e);
        } finally {
          server.close();
        }
      });
      server.on('error', (e) => {
        // Handle server errors (e.g., port already in use)
        reject(new Error(`HTTP server error: ${e.message}`));
        server.close();
      });
      server.listen(port, () => {
        // Server is listening, ready for OAuth callback
      });
    });

    return {
      authUrl,
      loginCompletePromise,
    };
  }
}

export function getAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    let port = 0;
    try {
      const server = net.createServer();
      server.listen(0, () => {
        const address = server.address()! as net.AddressInfo;
        port = address.port;
      });
      server.on('listening', () => {
        server.close();
        server.unref();
      });
      server.on('error', (e) => reject(e));
      server.on('close', () => resolve(port));
    } catch (e) {
      reject(e);
    }
  });
}

async function loadCachedCredentials(client: OAuth2Client): Promise<boolean> {
  try {
    const keyFile =
      process.env.GOOGLE_APPLICATION_CREDENTIALS || getCachedCredentialPath();

    const creds = await fs.readFile(keyFile, 'utf-8');
    client.setCredentials(JSON.parse(creds));

    // This will verify locally that the credentials look good.
    const { token } = await client.getAccessToken();
    if (!token) {
      return false;
    }

    // This will check with the server to see if it hasn't been revoked.
    await client.getTokenInfo(token);

    return true;
  } catch (_) {
    return false;
  }
}

async function cacheCredentials(credentials: Credentials) {
  const filePath = getCachedCredentialPath();
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  const credString = JSON.stringify(credentials, null, 2);
  await fs.writeFile(filePath, credString);
}

function getCachedCredentialPath(): string {
  return path.join(os.homedir(), GEMINI_DIR, CREDENTIAL_FILENAME);
}

export async function clearCachedCredentialFile() {
  try {
    await fs.rm(getCachedCredentialPath());
  } catch (_) {
    /* empty */
  }
}
