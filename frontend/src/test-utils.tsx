/**
 * Custom render wrapper for tests
 *
 * Provides all required providers (except AuthProvider, which makes API calls
 * on mount). Tests that need auth should mock useAuth directly.
 */

import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter, type MemoryRouterProps } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { SettingsProvider } from "@/contexts/SettingsContext";
import type { ReactElement, ReactNode } from "react";

interface RenderWithProvidersOptions extends Omit<RenderOptions, "wrapper"> {
  /** Initial entries for MemoryRouter */
  routerProps?: MemoryRouterProps;
  /** Supply a custom QueryClient (defaults to one with retry: false) */
  queryClient?: QueryClient;
  /** Skip wrapping with SettingsProvider (useful when testing SettingsContext itself) */
  withSettings?: boolean;
  /** Skip wrapping with ThemeProvider */
  withTheme?: boolean;
}

function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: Infinity,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

function renderWithProviders(
  ui: ReactElement,
  {
    routerProps = {},
    queryClient,
    withSettings = true,
    withTheme = true,
    ...renderOptions
  }: RenderWithProvidersOptions = {},
) {
  const client = queryClient ?? createTestQueryClient();

  function Wrapper({ children }: { children: ReactNode }) {
    let content = children;

    if (withSettings) {
      content = <SettingsProvider>{content}</SettingsProvider>;
    }

    if (withTheme) {
      content = <ThemeProvider>{content}</ThemeProvider>;
    }

    return (
      <QueryClientProvider client={client}>
        <MemoryRouter {...routerProps}>{content}</MemoryRouter>
      </QueryClientProvider>
    );
  }

  return {
    ...render(ui, { wrapper: Wrapper, ...renderOptions }),
    queryClient: client,
  };
}

export { renderWithProviders, createTestQueryClient };
// eslint-disable-next-line react-refresh/only-export-components
export * from "@testing-library/react";
