/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useCallback, useEffect } from 'react';
import { LoadedSettings, SettingScope } from '../../config/settings.js';
import {
  AuthType,
  Config,
  clearCachedCredentialFile,
  getErrorMessage,
} from '@google/gemini-cli-core';

async function performAuthFlow(authMethod: AuthType, config: Config) {
  // Ensure any previous headless step is cleared before starting a new auth flow.
  // This is also cleared in Config.refreshAuth, but good to be defensive.
  config.currentHeadlessAuthStep = undefined;
  await config.refreshAuth(authMethod);
  // The console.log about "Authenticated via..." might be premature if headless flow is initiated.
  // Consider moving it or making it conditional based on headless step.
  // For now, we'll let it be, as the CLI will soon take over with headless prompts if needed.
}

export const useAuthCommand = (
  settings: LoadedSettings,
  setAuthError: (error: string | null) => void,
  config: Config,
) => {
  const [isAuthDialogOpen, setIsAuthDialogOpen] = useState(
    settings.merged.selectedAuthType === undefined,
  );

  // New states for headless flow
  const [headlessAuthUrl, setHeadlessAuthUrl] = useState<string | null>(null);
  const [
    initiateHeadlessCodeEntry,
    setInitiateHeadlessCodeEntry,
  ] = useState<((code: string) => Promise<void>) | null>(null);

  const openAuthDialog = useCallback(() => {
    setIsAuthDialogOpen(true);
    // Clear any pending headless state when opening the main auth dialog
    setHeadlessAuthUrl(null);
    setInitiateHeadlessCodeEntry(null);
  }, []);

  const [isAuthenticating, setIsAuthenticating] = useState(false);

  useEffect(() => {
    const authFlow = async () => {
      if (isAuthDialogOpen || !settings.merged.selectedAuthType || headlessAuthUrl) {
        // Don't run if dialog is open, no auth type selected, or already in headless prompt phase
        return;
      }

      try {
        setIsAuthenticating(true); // Show generic spinner initially
        setHeadlessAuthUrl(null); // Clear previous headless state before new attempt
        setInitiateHeadlessCodeEntry(null);

        await performAuthFlow(
          settings.merged.selectedAuthType as AuthType,
          config,
        );

        // Check for headless step after performAuthFlow completes
        if (config.currentHeadlessAuthStep?.type === 'NEEDS_CODE') {
          setHeadlessAuthUrl(config.currentHeadlessAuthStep.authUrl);
          setInitiateHeadlessCodeEntry(
            // Store the actual function to be called
            () => config.currentHeadlessAuthStep!.exchangeCodeFunction,
          );
          setIsAuthenticating(false); // Turn off generic spinner; UI will show headless prompt
          console.log(`Authenticated via "${settings.merged.selectedAuthType}". Headless step required.`); // Log completion here for headless
        } else {
          // Standard auth completed (or failed before headless step)
          setHeadlessAuthUrl(null);
          setInitiateHeadlessCodeEntry(null);
          setIsAuthenticating(false);
          if (!config.currentHeadlessAuthStep) { // Avoid double logging if it was just cleared due to non-NEEDS_CODE type
            console.log(`Authenticated via "${settings.merged.selectedAuthType}".`);
          }
        }
      } catch (e) {
        setAuthError(`Failed to login. Message: ${getErrorMessage(e)}`);
        setIsAuthenticating(false);
        setHeadlessAuthUrl(null); // Clear headless state on error
        setInitiateHeadlessCodeEntry(null);
        openAuthDialog(); // Re-open dialog on error
      }
    };

    void authFlow();
  }, [isAuthDialogOpen, settings, config, setAuthError, openAuthDialog, headlessAuthUrl]);

  const submitHeadlessCode = useCallback(
    async (code: string) => {
      if (!initiateHeadlessCodeEntry) {
        const errMsg = 'Headless code submission error: No submission function available.';
        setAuthError(errMsg);
        // Clear headless state and force user back to AuthDialog to restart.
        setHeadlessAuthUrl(null);
        setInitiateHeadlessCodeEntry(null);
        openAuthDialog();
        console.error(errMsg); // also log to console
        return;
      }
      setIsAuthenticating(true); // Show spinner during code exchange
      try {
        // Call the stored function. initiateHeadlessCodeEntry holds () => actualFunction.
        // So we need to call it to get the actual function, then call that with code.
        const exchangeFunction = initiateHeadlessCodeEntry;
        await exchangeFunction(code);

        setAuthError(null); // Clear any previous auth errors
        console.log('Headless login successful.');
        // Successful authentication, clear headless state
        setHeadlessAuthUrl(null);
        setInitiateHeadlessCodeEntry(null);
        setIsAuthDialogOpen(false); // Ensure main dialog is closed
      } catch (e) {
        const errorMsg = `Headless login failed: ${getErrorMessage(e)}. Please check the code and try again.`;
        setAuthError(errorMsg);
        // Keep headlessAuthUrl and initiateHeadlessCodeEntry so the user can retry on the same prompt.
        // If we wanted to force them back to AuthDialog on error:
        // setHeadlessAuthUrl(null);
        // setInitiateHeadlessCodeEntry(null);
        // openAuthDialog();
        console.error(errorMsg);
      } finally {
        setIsAuthenticating(false); // Hide spinner
      }
    },
    [initiateHeadlessCodeEntry, setAuthError, openAuthDialog],
  );

  const handleAuthSelect = useCallback(
    async (authMethod: string | undefined, scope: SettingScope) => {
      if (authMethod) {
        await clearCachedCredentialFile(); // Clear creds for any new auth method selection
        settings.setValue(scope, 'selectedAuthType', authMethod);
        setHeadlessAuthUrl(null); // Clear any old headless state
        setInitiateHeadlessCodeEntry(null);
      }
      setIsAuthDialogOpen(false); // This will trigger the useEffect for authFlow
      setAuthError(null);
    },
    [settings, setAuthError], // Removed openAuthDialog, setIsAuthDialogOpen is sufficient
  );

  const handleAuthHighlight = useCallback((_authMethod: string | undefined) => {
    // For now, we don't do anything on highlight.
  }, []);

  const cancelAuthentication = useCallback(() => {
    setIsAuthenticating(false);
    setHeadlessAuthUrl(null);
    setInitiateHeadlessCodeEntry(null);
    // If cancelling from headless prompt, re-open AuthDialog.
    // Check if isAuthDialogOpen is false to avoid loop if already open.
    if (!isAuthDialogOpen) {
      openAuthDialog();
    }
  }, [isAuthDialogOpen, openAuthDialog]);

  return {
    isAuthDialogOpen,
    openAuthDialog,
    handleAuthSelect,
    handleAuthHighlight,
    isAuthenticating,
    cancelAuthentication,
    headlessAuthUrl, // Expose new state
    // Expose initiateHeadlessCodeEntry for potential direct use if needed, though submitHeadlessCode is preferred
    initiateHeadlessCodeEntry,
    submitHeadlessCode, // Expose new function
  };
};
