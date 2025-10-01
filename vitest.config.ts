/// <reference types="vitest" />
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Configurações do Vitest
    globals: true,
    environment: 'node',
    
    // Timeout para testes que fazem crypto (como PBKDF2)
    testTimeout: 10000,
    
    // Incluir arquivos de teste
    include: ['tests/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts}'],
    
    // Excluir arquivos
    exclude: ['node_modules', 'dist'],
    
    // Reporters para CI
    reporters: process.env.CI ? ['github-actions'] : ['verbose'],
    
    // Coverage (opcional)
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        'tests/',
        '**/*.d.ts',
      ]
    }
  }
})