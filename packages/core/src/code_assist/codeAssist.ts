/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { AuthType, ContentGenerator } from '../core/contentGenerator.js';
import { getOauthClient } from './oauth2.js'; // OauthWebLogin is not needed here
import { setupUser } from './setup.js';
import { CodeAssistServer, HttpOptions } from './server.js';
import type { Config } from '../config/config.js';

export async function createCodeAssistContentGenerator(
  httpOptions: HttpOptions,
  authType: AuthType,
  config: Config, // Add Config parameter
): Promise<ContentGenerator> {
  if (authType === AuthType.LOGIN_WITH_GOOGLE_PERSONAL) {
    // getOauthClient will be modified to accept config and set
    // config.currentHeadlessAuthStep internally if a headless flow is initiated.
    const authClient = await getOauthClient(config); // Pass config to getOauthClient
    const projectId = await setupUser(authClient);
    return new CodeAssistServer(authClient, projectId, httpOptions);
  }

  throw new Error(`Unsupported authType: ${authType}`);
}
