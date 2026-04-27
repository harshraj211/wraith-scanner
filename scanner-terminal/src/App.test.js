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

import { fireEvent, render, screen } from '@testing-library/react';
import App from './App';

test('renders the Wraith website and opens automated mode', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /wraith v4/i })).toBeInTheDocument();
  fireEvent.click(screen.getAllByRole('button', { name: /start scan/i })[0]);
  expect(screen.getByRole('heading', { name: /start wraith/i })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /open automated/i }));
  expect(screen.getByRole('heading', { name: /scan setup/i })).toBeInTheDocument();
  expect(screen.getByLabelText(/base url/i)).toBeInTheDocument();
  expect(screen.getByText(/api imports/i)).toBeInTheDocument();
  expect(screen.getByText(/sequence workflows/i)).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: /requests/i })).toBeInTheDocument();
});
