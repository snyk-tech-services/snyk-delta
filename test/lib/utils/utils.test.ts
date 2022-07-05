import { getPipedDataIn } from '../../../src/lib/utils/utils';
import { stdin, MockSTDIN } from 'mock-stdin';

const stdinMock: MockSTDIN = stdin();

describe('Test utils functions', () => {
  beforeAll(() => {
    jest.resetAllMocks();
  });
  it('Test getPipedDataIn', async () => {
    setTimeout(() => {
      stdinMock.send('Some text', 'ascii');
      stdinMock.send(null);
    }, 500);
    const data = await getPipedDataIn();

    expect(data).toEqual('Some text');
  });
});
