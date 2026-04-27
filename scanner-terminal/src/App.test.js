jest.mock('xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => ({
    loadAddon: jest.fn(),
    open: jest.fn(),
    writeln: jest.fn(),
    write: jest.fn(),
    onData: jest.fn(() => ({ dispose: jest.fn() })),
    dispose: jest.fn(),
    clear: jest.fn(),
  })),
}));

jest.mock('xterm-addon-fit', () => ({
  FitAddon: jest.fn().mockImplementation(() => ({
    fit: jest.fn(),
  })),
}));

jest.mock('xterm-addon-web-links', () => ({
  WebLinksAddon: jest.fn().mockImplementation(() => ({})),
}));

jest.mock('socket.io-client', () => jest.fn(() => ({
  on: jest.fn(),
  disconnect: jest.fn(),
})));

import { render, screen } from '@testing-library/react';
import App from './App';

test('renders the Wraith scan setup workbench', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /scan setup/i })).toBeInTheDocument();
  expect(screen.getByLabelText(/base url/i)).toBeInTheDocument();
  expect(screen.getByText(/api imports/i)).toBeInTheDocument();
  expect(screen.getByText(/sequence workflows/i)).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: /requests/i })).toBeInTheDocument();
});
