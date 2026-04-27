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

beforeEach(() => {
  window.history.replaceState(null, '', '/');
});

test('renders the Wraith website and opens automated mode', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /wraith v4/i })).toBeInTheDocument();
  fireEvent.click(screen.getAllByRole('button', { name: /start scan/i })[0]);
  expect(screen.getByRole('heading', { name: /start wraith/i })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /open automated/i }));
  expect(screen.getByRole('heading', { name: /risk dashboard/i })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /scan details/i }));
  expect(screen.getByRole('heading', { name: /automated scan setup/i })).toBeInTheDocument();
  expect(screen.getByLabelText(/base url/i)).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: /api imports/i })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: /sequence workflows/i })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /evidence corpus/i }));
  expect(screen.getByRole('heading', { name: /evidence corpus/i })).toBeInTheDocument();
});

test('decoder chains repeated transforms from output', () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /manual workbench/i }));
  fireEvent.click(screen.getByRole('button', { name: /decoder/i }));

  const input = screen.getByLabelText(/input/i);
  fireEvent.change(input, { target: { value: '%252Fadmin' } });
  fireEvent.click(screen.getByRole('button', { name: /url decode/i }));
  expect(screen.getByLabelText(/output/i)).toHaveValue('%2Fadmin');

  fireEvent.click(screen.getByRole('button', { name: /url decode/i }));
  expect(screen.getByLabelText(/output/i)).toHaveValue('/admin');
});

test('manual repeater supports multiple request tabs', () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /manual workbench/i }));
  fireEvent.click(screen.getByRole('button', { name: /^repeater$/i }));

  expect(screen.getByRole('button', { name: /manual request/i })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /^new$/i }));
  expect(screen.getByRole('button', { name: /^new request$/i })).toBeInTheDocument();
});

test('manual intruder exposes capped payload runner controls', () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /manual workbench/i }));
  fireEvent.click(screen.getByRole('button', { name: /^intruder$/i }));

  expect(screen.getByRole('heading', { name: /payload runner/i })).toBeInTheDocument();
  expect(screen.getByLabelText(/payload marker/i)).toHaveValue('{{payload}}');
  expect(screen.getByLabelText(/max requests/i)).toHaveValue('25');
  expect(screen.getByRole('button', { name: /run attack/i })).toBeInTheDocument();
});
