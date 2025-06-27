/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Box, Text, useInput } from 'ink';
// A simple TextInput like component might be needed if ink-text-input is not available
// For now, let's assume we can build a simple one or find a suitable primitive.
// Using state for input value and useInput for handling.
import TextInput from 'ink-text-input'; // Assuming this or a similar package is available or can be added
import { Colors } from '../colors.js';

interface HeadlessAuthPromptProps {
  authUrl: string;
  onSubmitCode: (code: string) => Promise<void>;
  onCancel: () => void;
  errorMessage?: string | null;
  isAuthenticating: boolean; // To show a spinner/loading state during code exchange
}

export function HeadlessAuthPrompt({
  authUrl,
  onSubmitCode,
  onCancel,
  errorMessage,
  isAuthenticating,
}: HeadlessAuthPromptProps): React.JSX.Element {
  const [inputValue, setInputValue] = useState('');

  useInput((_input, key) => {
    if (key.escape) {
      onCancel();
    }
  });

  const handleSubmit = async () => {
    if (inputValue.trim() !== '' && !isAuthenticating) {
      await onSubmitCode(inputValue.trim());
      // inputValue might be cleared by the parent if submission leads to unmount or state change
      // If submission fails and component remains, user might want to edit, so don't clear here.
    }
  };

  return (
    <Box
      borderStyle="round"
      borderColor={Colors.Gray}
      flexDirection="column"
      padding={1}
      width="100%"
    >
      <Text bold>Headless Authentication</Text>
      <Box marginTop={1}>
        <Text>
          Please open the following URL in your browser to authorize the
          application:
        </Text>
      </Box>
      <Box marginTop={1}>
        <Text color={Colors.AccentBlue}>{authUrl}</Text>
      </Box>
      <Box marginTop={1}>
        <Text>
          After authorization, copy the code provided by Google and paste it
          below, then press Enter.
        </Text>
      </Box>

      <Box marginTop={1} flexDirection="row">
        <Text>Enter code: </Text>
        {isAuthenticating ? (
          <Text>
            <Text color={Colors.AccentCyan}> Verifying code...</Text>
          </Text>
        ) : (
          <TextInput
            value={inputValue}
            onChange={setInputValue}
            onSubmit={handleSubmit}
            placeholder="Paste code here"
          />
        )}
      </Box>

      {errorMessage && (
        <Box marginTop={1}>
          <Text color={Colors.AccentRed}>{errorMessage}</Text>
        </Box>
      )}

      {!isAuthenticating && (
         <Box marginTop={1}>
           <Text color={Colors.Gray}>(Press Enter to submit, ESC to cancel)</Text>
         </Box>
      )}
    </Box>
  );
}
